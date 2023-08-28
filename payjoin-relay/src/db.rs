use anyhow::Result;
use sqlx::postgres::{PgListener, PgPoolOptions};
use sqlx::{PgPool, Pool, Postgres};
use tracing::debug;

const RES_COLUMN: &str = "res";
const REQ_COLUMN: &str = "req";

pub(crate) struct DbPool {
    pool: Pool<Postgres>,
}

impl DbPool {
    pub async fn new() -> Result<Self> {
        let pool = init_postgres().await?;
        Ok(Self { pool })
    }

    pub async fn peek_req(&self, pubkey_id: &str) -> Result<Vec<u8>, sqlx::Error> {
        peek(&self.pool, pubkey_id, REQ_COLUMN).await
    }

    pub async fn peek_res(&self, pubkey_id: &str) -> Result<Vec<u8>, sqlx::Error> {
        peek(&self.pool, pubkey_id, RES_COLUMN).await
    }

    pub async fn push_req(&self, pubkey_id: &str, data: Vec<u8>) -> Result<(), sqlx::Error> {
        push(&self.pool, pubkey_id, REQ_COLUMN, data).await
    }

    pub async fn push_res(&self, pubkey_id: &str, data: Vec<u8>) -> Result<(), sqlx::Error> {
        push(&self.pool, pubkey_id, RES_COLUMN, data).await
    }
}

impl Clone for DbPool {
    fn clone(&self) -> Self { Self { pool: self.pool.clone() } }
}

async fn init_postgres() -> Result<PgPool> {
    let pool =
        PgPoolOptions::new().connect("postgres://postgres:welcome@localhost/postgres").await?;
    // Create table if not exist yet
    let (table_exists,): (bool,) =
        sqlx::query_as("SELECT EXISTS (SELECT FROM pg_tables WHERE tablename = 'relay')")
            .fetch_one(&pool)
            .await?;

    if !table_exists {
        // Create the table
        sqlx::query(
            r#"
            CREATE TABLE relay (
                pubkey_id VARCHAR PRIMARY KEY,
                req BYTEA,
                res BYTEA
            );
        "#,
        )
        .execute(&pool)
        .await?;

        // Create the function for notification
        sqlx::query(
            r#"
            CREATE OR REPLACE FUNCTION notify_change()
            RETURNS TRIGGER AS $$
            DECLARE
                channel_name text;
            BEGIN
                channel_name := NEW.pubkey_id || '_' || TG_ARGV[0];
                PERFORM pg_notify(channel_name, TG_TABLE_NAME || ', ' || NEW.pubkey_id);
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql;
        "#,
        )
        .execute(&pool)
        .await?;

        // Create triggers
        sqlx::query(
            r#"
            CREATE TRIGGER relay_req_trigger
            AFTER INSERT OR UPDATE OF req ON relay
            FOR EACH ROW
            EXECUTE FUNCTION notify_change('req');
        "#,
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TRIGGER relay_res_trigger
            AFTER INSERT OR UPDATE OF res ON relay
            FOR EACH ROW
            EXECUTE FUNCTION notify_change('res');
        "#,
        )
        .execute(&pool)
        .await?;
    }
    Ok(pool)
}

async fn push(
    pool: &Pool<Postgres>,
    pubkey_id: &str,
    channel_type: &str,
    data: Vec<u8>,
) -> Result<(), sqlx::Error> {
    // Use an UPSERT operation to insert or update the record
    let query = format!(
        "INSERT INTO relay (pubkey_id, {}) VALUES ($1, $2) \
        ON CONFLICT (pubkey_id) DO UPDATE SET {} = EXCLUDED.{}",
        channel_type, channel_type, channel_type
    );

    sqlx::query(&query).bind(pubkey_id).bind(data).execute(pool).await?;

    Ok(())
}

async fn peek(
    pool: &Pool<Postgres>,
    pubkey_id: &str,
    channel_type: &str,
) -> Result<Vec<u8>, sqlx::Error> {
    let mut listener = PgListener::connect_with(pool).await?;
    // Listen on the channel specific to this pubkey_id and channel_type (either "req" or "res")
    listener.listen(&format!("{}_{}", pubkey_id, channel_type)).await?;
    debug!("Listening on channel: {}", format!("{}_{}", pubkey_id, channel_type));
    loop {
        // Awaiting notification
        let notification = listener.recv().await?;
        debug!("Received notification: {:?}", notification);
        if notification.channel() == format!("{}_{}", pubkey_id, channel_type) {
            // Fetch the new content for the updated column
            let row: (Vec<u8>,) =
                sqlx::query_as(&format!("SELECT {} FROM relay WHERE pubkey_id = $1", channel_type))
                    .bind(pubkey_id)
                    .fetch_one(pool)
                    .await?;

            let updated_content = row.0;
            if !updated_content.is_empty() {
                return Ok(updated_content);
            }
        }
    }
}
