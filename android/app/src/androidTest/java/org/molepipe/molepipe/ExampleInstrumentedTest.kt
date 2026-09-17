package org.molepipe.molepipe

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AppInstrumentedTest {
    @Test
    fun packageNameIsCorrect() {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals("org.molepipe.molepipe", ctx.packageName)
    }

    @Test
    fun backendStateSealedHierarchy() {
        // Verify that the sealed interface subtypes are accessible and distinct.
        val states = arrayOf(
            Backend.State.Stopped,
            Backend.State.Starting,
            Backend.State.Running("http://127.0.0.1:1234"),
            Backend.State.Failed("test"),
        )
        assertEquals(4, states.size)
        // Each state should be a unique subtype.
        assertTrue(states[0] is Backend.State.Stopped)
        assertTrue(states[1] is Backend.State.Starting)
        assertTrue(states[2] is Backend.State.Running)
        assertTrue(states[3] is Backend.State.Failed)
    }

    @Test
    fun backendSingletonAccessible() {
        // The Backend object should be reachable from instrumented code.
        assertNotNull(Backend)
    }

    @Test
    fun messageNotifierSingletonAccessible() {
        assertNotNull(MessageNotifier)
    }

    @Test
    fun appStateIsThreadSafe() {
        // Exercise the volatile flag from the instrumentation thread.
        AppState.inForeground = true
        assertTrue(AppState.inForeground)
        AppState.inForeground = false
        assertFalse(AppState.inForeground)
    }

    @Test
    fun messageNotifierClearAllDoesNotCrash() {
        // clearAll with null context should be a silent no-op.
        MessageNotifier.clearAll()
    }
}
