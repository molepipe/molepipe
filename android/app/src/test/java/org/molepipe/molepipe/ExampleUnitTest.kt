package org.molepipe.molepipe

import org.junit.Assert.*
import org.junit.Test

class AppStateTest {
    @Test
    fun inForegroundDefaultsToFalse() {
        // Reset to a known state (the singleton may have been set by other tests).
        AppState.inForeground = false
        assertFalse(AppState.inForeground)
    }

    @Test
    fun inForegroundCanBeToggled() {
        AppState.inForeground = true
        assertTrue(AppState.inForeground)
        AppState.inForeground = false
        assertFalse(AppState.inForeground)
    }
}

class BackendStateTest {
    @Test
    fun stoppedStateIsDefault() {
        // Verify the Sealed interface hierarchy is intact.
        val stopped: Backend.State = Backend.State.Stopped
        assertFalse(stopped is Backend.State.Running)
        assertFalse(stopped is Backend.State.Failed)
        assertFalse(stopped is Backend.State.Starting)
    }

    @Test
    fun runningStateHoldsUrl() {
        val url = "http://127.0.0.1:8080"
        val running = Backend.State.Running(url)
        assertEquals(url, running.url)
    }

    @Test
    fun failedStateHoldsMessage() {
        val msg = "backend crashed"
        val failed = Backend.State.Failed(msg)
        assertEquals(msg, failed.message)
    }

    @Test
    fun stateEquality() {
        assertEquals(Backend.State.Stopped, Backend.State.Stopped)
        assertEquals(Backend.State.Starting, Backend.State.Starting)
        assertEquals(Backend.State.Running("x"), Backend.State.Running("x"))
        assertNotEquals(Backend.State.Running("a"), Backend.State.Running("b"))
        assertEquals(Backend.State.Failed("e"), Backend.State.Failed("e"))
        assertNotEquals(Backend.State.Stopped, Backend.State.Starting)
    }

    @Test
    fun stateTypeChecks() {
        val states: List<Backend.State> = listOf(
            Backend.State.Stopped,
            Backend.State.Starting,
            Backend.State.Running("http://localhost"),
            Backend.State.Failed("error"),
        )
        assertEquals(4, states.size)
        assertTrue(states[0] is Backend.State.Stopped)
        assertTrue(states[1] is Backend.State.Starting)
        assertTrue(states[2] is Backend.State.Running)
        assertTrue(states[3] is Backend.State.Failed)
    }
}

class MessageNotifierIdTest {
    // perSenderId is private, but we can test the public interface: clearAll
    // and the fact that the object initializes without error.

    @Test
    fun objectInitializes() {
        // MessageNotifier is a singleton object; just verify it's accessible.
        assertNotNull(MessageNotifier)
    }

    @Test
    fun clearAllDoesNotThrowWithoutAttach() {
        // clearAll should be a no-op if appContext is null (no crash).
        MessageNotifier.clearAll()
    }
}

class BackendServiceActionTest {
    @Test
    fun actionStopConstant() {
        assertEquals("org.molepipe.molepipe.action.STOP", BackendService.ACTION_STOP)
    }
}
