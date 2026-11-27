package netzbegruenung.keycloak.authenticator.gateway;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

/**
 * Collects the formatted log lines of the plugin's code ("netzbegruenung" loggers) while it is open.
 * Relies on JBoss Logging using java.util.logging in the test JVM (org.jboss.logging.provider=jdk,
 * set by surefire in the module pom).
 */
final class LogCapture implements AutoCloseable {

	// Kept in a field: java.util.logging only holds loggers weakly, the level and handler would be lost.
	private final Logger logger = Logger.getLogger("netzbegruenung");
	private final Level previousLevel = logger.getLevel();
	private final List<String> lines = new CopyOnWriteArrayList<>();
	private final SimpleFormatter formatter = new SimpleFormatter();
	private final Handler handler = new Handler() {
		@Override
		public void publish(LogRecord logRecord) {
			lines.add(formatter.formatMessage(logRecord));
		}

		@Override
		public void flush() {
		}

		@Override
		public void close() {
		}
	};

	LogCapture() {
		logger.setLevel(Level.ALL);
		logger.addHandler(handler);
	}

	List<String> lines() {
		return List.copyOf(lines);
	}

	@Override
	public void close() {
		logger.removeHandler(handler);
		logger.setLevel(previousLevel);
	}
}
