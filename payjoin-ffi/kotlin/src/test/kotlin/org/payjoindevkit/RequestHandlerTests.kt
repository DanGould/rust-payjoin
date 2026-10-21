package org.payjoindevkit

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
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

private class FirstRelayDownTransport(private val receiver: Initialized) : RelayTransport {
    val relaysTried = mutableListOf<String>()

    override fun build(relay: Url): BuiltRequest {
        relaysTried.add(relay.asString())
        val poll = receiver.createPollRequest(relay.asString())
        return BuiltRequest(poll.request, poll.clientResponse)
    }

    override suspend fun post(request: Request): ByteArray {
        if (relaysTried.size == 1) throw RelayTransportException.Transient("relay down")
        return "response".toByteArray()
    }
}

class RequestHandlerTests {
    @Test
    fun pinnedOhttpKeysReturnTheirDirectory() = runTest {
        val directory = Url.parse(DIRECTORY)
        val handler = RequestHandler(relays, listOf("https://other.example"))
        handler.setOhttpKeys(directory, OhttpKeys.decode(ohttpKeysData))
        val fetcher = FirstRelayDownFetcher()

        val fetched = handler.fetchOhttpKeys(fetcher)

        assertEquals(directory.asString(), fetched.directory.asString())
        assertTrue(fetcher.relaysTried.isEmpty())
    }

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
    fun postViaRelayFailsOverAndSkipsTheDirectory() = runTest {
        val directory = Url.parse(DIRECTORY)
        val receiver = ReceiverBuilder(
            "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4",
            directory.asString(),
            OhttpKeys.decode(ohttpKeysData),
        ).build().save(InMemoryReceiverPersister())
        // The directory is also listed as a relay; it must never be used to
        // reach itself.
        val handler = RequestHandler(relays + directory.asString(), listOf(directory.asString()))
        val transport = FirstRelayDownTransport(receiver)

        val response = handler.postViaRelay(directory, transport)

        assertEquals("response", response.body.decodeToString())
        assertEquals(2, transport.relaysTried.size)
        assertNotEquals(transport.relaysTried[0], transport.relaysTried[1])
        assertFalse(directory.asString() in transport.relaysTried)
    }
}
