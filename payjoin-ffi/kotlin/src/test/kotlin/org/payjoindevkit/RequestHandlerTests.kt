package org.payjoindevkit

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

private val relays = listOf(
    "https://relay-a.example",
    "https://relay-b.example",
    "https://relay-c.example",
)

private const val DIRECTORY = "https://directory.example"

class RequestHandlerTests {
    @Test
    fun keyFetchOrderTriesTheDirectoryOverEveryOtherRelay() {
        val directory = Url.parse(DIRECTORY)
        // The directory is also listed as a relay; it must never be used to
        // reach itself.
        val handler = RequestHandler(relays + directory.asString(), listOf(directory.asString()))

        val order = handler.keyFetchOrder()

        assertEquals(setOf(directory.asString()), order.map { it.directory.asString() }.toSet())
        assertEquals(relays.map { Url.parse(it).asString() }.sorted(), order.map { it.relay.asString() }.sorted())
    }

    @Test
    fun keyFetchOrderWithoutRelaysIsEmpty() {
        val handler = RequestHandler(emptyList(), listOf(DIRECTORY))

        assertTrue(handler.keyFetchOrder().isEmpty())
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
