package org.irmacard.api.web;

import javax.servlet.ServletContextListener;
import javax.servlet.ServletContextEvent;

public class OurServletContextListener  implements ServletContextListener {
    public void contextDestroyed(ServletContextEvent sce) {
        Historian.getInstance().disable();
    }
    public void contextInitialized(ServletContextEvent sce) {
    }
}

