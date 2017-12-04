package org.irmacard.api.web;

import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.client.HttpClient;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.HttpResponse;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.Condition;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.io.UnsupportedEncodingException;
import java.io.IOException;

// Historian is a singleton thread which collects and sends events
// to an outside HTTP server.  It is disabled by default.  Enable with
// the enable() method.
public class Historian implements Runnable {
    private static  Historian instance;

    private static Logger logger = LoggerFactory.getLogger(Historian.class);

    // synchronization
    private Thread thread;
    private Lock lock;
    private Condition cond;

    // the data -- should only be accessed when lock is held
    private class IssueEvent {
        public Date When;
        public String Attribute;
        public String IP;

        public IssueEvent(Date When, String Attribute, String IP) {
            this.When = When; this.Attribute = Attribute; this.IP = IP;
        }
    }
    private class SubmitRequest {
        ArrayList<IssueEvent> Issuances;

        public SubmitRequest(ArrayList<IssueEvent> Issuances) {
            this.Issuances = Issuances;
        }
    }
    private ArrayList<IssueEvent> issueEvents = new ArrayList<IssueEvent>();
    
    // configuration
    private boolean enabled = false;
    private String uri;
    private String authorizationToken;

    // json dumper
    private Gson gson;

    private Historian() {
        this.lock = new ReentrantLock();
        this.cond = lock.newCondition();
        this.gson = new GsonBuilder().setDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'").create();
    }

    public static Historian getInstance() {
        if (instance == null) {
            synchronized (Historian.class) {
                if (instance == null) {
                    instance = new Historian();
                }
            }
        }
        return instance;
    }

    // Pushes the data.
    private boolean pushEvents(String payload) {
        try {
            HttpClient httpClient = HttpClientBuilder.create().build();
            HttpPost httpPost = new HttpPost(this.uri);
            if (this.authorizationToken != null) {
                httpPost.setHeader("Authorization",
                                    "Basic " + this.authorizationToken);
            }
            List<NameValuePair> params = new ArrayList<NameValuePair>(1);
            params.add(new BasicNameValuePair("events", payload));
            httpPost.setEntity(new UrlEncodedFormEntity(params, "UTF-8"));
            HttpResponse response = httpClient.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();
            if (statusCode != 200) {
                logger.warn("Failed to push: HTTP code "
                                + Integer.toString(statusCode));
                return false;
            }
        } catch (UnsupportedEncodingException e) {
            return false;
        } catch (IOException e) {
            return false;
        }
        return true;
    }

    public void run() {
        logger.info("Historian worker thread started");
        String toSend = null;
        int issueEventsSent = 0;
        boolean pushAttempted = false;
        boolean pushWasSuccessful = false;

        while (true) {
            this.lock.lock();
            try {
                if (!this.enabled) break;

                // Did we succesfully push some data?  If so, we need to clear
                // it from the lists.
                if (pushAttempted) {
                    pushAttempted = false;
                    if (pushWasSuccessful) {
                        issueEvents.subList(0, issueEventsSent).clear();
                    }
                }

                // Wait for a new batch of data.
                if (!pushWasSuccessful || issueEvents.size() == 0) {
                    this.cond.await();
                }

                issueEventsSent = this.issueEvents.size();
                if (issueEventsSent != 0) {
                    toSend = gson.toJson(new SubmitRequest(this.issueEvents));
                    pushAttempted = true;
                }
            } catch (InterruptedException e ) { 
            } finally {
                this.lock.unlock();
            }

            if (toSend != null) {
                pushWasSuccessful = pushEvents(toSend);
                toSend = null;
            }
        }
    }

    public void disable() {
        if (!this.enabled) return;
        this.enabled = false;
        this.lock.lock();
        try {
            this.cond.signal();
        } finally {
            this.lock.unlock();
        }
    }

    public void enable(String uri, String authorizationToken) {
        if (enabled) {
            throw new IllegalStateException("Already enabled");
        }

        this.enabled = true;
        this.thread = new Thread(this);
        this.authorizationToken = authorizationToken;
        this.uri = uri;

        thread.start();
    }

    public void recordIssue(String attribute, String ip) {
        if (!this.enabled)
            return;
        this.lock.lock();
        try {
            issueEvents.add(new IssueEvent(new Date(), attribute, ip));
            this.cond.signal();
        } finally {
            this.lock.unlock();
        }
    }
}
