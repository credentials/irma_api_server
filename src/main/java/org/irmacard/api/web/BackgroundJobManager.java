package org.irmacard.api.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@WebListener
public class BackgroundJobManager implements ServletContextListener {
	private static Logger logger = LoggerFactory.getLogger(BackgroundJobManager.class);
	static private ScheduledExecutorService scheduler;

	public static ScheduledExecutorService getScheduler() {
		if (scheduler == null) {
			synchronized (BackgroundJobManager.class) {
				if (scheduler == null) {
					scheduler = Executors.newScheduledThreadPool(2);
				}
			}
		}
		return scheduler;
	}

	@Override
	public void contextInitialized(ServletContextEvent event) {
	}

	@Override
	public void contextDestroyed(ServletContextEvent event) {
		getScheduler().shutdownNow();
	}
}
