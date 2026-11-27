package netzbegruenung.keycloak.authenticator;

import org.keycloak.models.SingleUseObjectProvider;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * A SingleUseObjectProvider backed by a plain map, for unit tests: put, get, remove and putIfAbsent behave like
 * Keycloak's store, lifespans are ignored. The entries map is the store's content, open to assertions and set-up.
 */
final class InMemorySingleUseObjects {

	private InMemorySingleUseObjects() {
	}

	static SingleUseObjectProvider backedBy(Map<String, Map<String, String>> entries) {
		SingleUseObjectProvider store = mock(SingleUseObjectProvider.class);
		when(store.get(anyString())).thenAnswer(call -> entries.get(call.<String>getArgument(0)));
		doAnswer(call -> {
			entries.put(call.getArgument(0), new HashMap<>(call.<Map<String, String>>getArgument(2)));
			return null;
		}).when(store).put(anyString(), anyLong(), anyMap());
		when(store.remove(anyString())).thenAnswer(call -> entries.remove(call.<String>getArgument(0)));
		when(store.putIfAbsent(anyString(), anyLong()))
			.thenAnswer(call -> entries.putIfAbsent(call.getArgument(0), new HashMap<>()) == null);
		return store;
	}
}
