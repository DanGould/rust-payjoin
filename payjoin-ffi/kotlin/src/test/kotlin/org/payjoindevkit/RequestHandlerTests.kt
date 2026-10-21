package org.payjoindevkit

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlinx.coroutines.test.runTest

private val relays = listOf(
    "https://relay-a.example",
    "https://relay-b.example",
    "https://relay-c.example",
)

private const val DIRECTORY = "https://directory.example"

private class FirstRelayDownFetcher : OhttpKeysFetcher {
    val relaysTried = mutableListOf<String>()

    override suspend fun fetch(relay: Url, directory: Url): OhttpKeys {
        relaysTried.add(relay.asString())
        if (relaysTried.size == 1) throw DirectoryFetchException.Transient("relay down")
        return OhttpKeys.decode(ohttpKeysData)
    }
}

class RequestHandlerTests {
    @Test
    fun fetchOhttpKeysFailsOverToAnotherRelay() = runTest {
        val directory = Url.parse(DIRECTORY)
        val handler = RequestHandler(relays, listOf(directory.asString()))
        val fetcher = FirstRelayDownFetcher()

        val fetched = handler.fetchOhttpKeys(fetcher)

        assertEquals(directory.asString(), fetched.directory.asString())
        assertEquals(2, fetcher.relaysTried.size)
        assertNotEquals(fetcher.relaysTried[0], fetcher.relaysTried[1])
    }

    @Test
    fun fetchOhttpKeysWithoutRelaysThrows() = runTest {
        val handler = RequestHandler(emptyList(), listOf(DIRECTORY))

        assertFailsWith<RequestHandlerException> { handler.fetchOhttpKeys(FirstRelayDownFetcher()) }
    }

    @Test
    fun relayOrderSkipsTheDirectory() {
        val directory = Url.parse(DIRECTORY)
        // The directory is also listed as a relay; it must never be used to
        // reach itself.
        val handler = RequestHandler(relays + directory.asString(), listOf(directory.asString()))

        val order = handler.relayOrder(directory).map { it.asString() }.sorted()

        assertEquals(relays.map { Url.parse(it).asString() }.sorted(), order)
    }
}
