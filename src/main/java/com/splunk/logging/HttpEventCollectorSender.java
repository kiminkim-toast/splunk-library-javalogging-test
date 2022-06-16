package com.splunk.logging;

/**
 * @copyright
 *
 * Copyright 2013-2015 Splunk, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"): you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

import org.json.simple.JSONObject;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import java.io.IOException;
import java.io.Serializable;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Dictionary;
import java.util.Timer;
import java.util.TimerTask;
import java.util.List;
import java.util.LinkedList;
import java.util.Map;
import java.util.Locale;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Dispatcher;
import okhttp3.Headers;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

/**
 * This is an internal helper class that sends logging events to Splunk http event collector.
 */
public class HttpEventCollectorSender extends TimerTask implements HttpEventCollectorMiddleware.IHttpSender {
    public static final String MetadataTimeTag = "time";
    public static final String MetadataHostTag = "host";
    public static final String MetadataIndexTag = "index";
    public static final String MetadataSourceTag = "source";
    public static final String MetadataSourceTypeTag = "sourcetype";
    public static final String MetadataMessageFormatTag = "messageFormat";
    private static final String SPLUNKREQUESTCHANNELTag = "X-Splunk-Request-Channel";
    private static final String AuthorizationHeaderTag = "Authorization";
    private static final String AuthorizationHeaderScheme = "Splunk %s";
    private static final String HttpEventCollectorUriPath = "/services/collector/event/1.0";
    private static final String HttpRawCollectorUriPath = "/services/collector/raw";
    private static final String HttpContentType = "application/json; profile=urn:splunk:event:1.0; charset=utf-8";
    private static final String SendModeSequential = "sequential";
    private static final String SendModeSParallel = "parallel";

    /**
     * Sender operation mode. Parallel means that all HTTP requests are
     * asynchronous and may be indexed out of order. Sequential mode guarantees
     * sequential order of the indexed events.
     */
    public enum SendMode
    {
        Sequential,
        Parallel
    };
    
    /**
     * Recommended default values for events batching.
     */
    public static final int DefaultBatchInterval = 10 * 1000; // 10 seconds
    public static final int DefaultBatchSize = 10 * 1024; // 10KB
    public static final int DefaultBatchCount = 10; // 10 events

    private String url;
    private String token;
    private String channel;
    private String type;
    private long maxEventsBatchCount;
    private long maxEventsBatchSize;
    private Dictionary<String, String> metadata;
    private Timer timer;
    private List<HttpEventCollectorEventInfo> eventsBatch = new LinkedList<HttpEventCollectorEventInfo>();
    private long eventsBatchSize = 0; // estimated total size of events batch
    private OkHttpClient httpClient;
    private boolean disableCertificateValidation = false;
    private SendMode sendMode = SendMode.Sequential;
    private HttpEventCollectorMiddleware middleware = new HttpEventCollectorMiddleware();
    private final MessageFormat messageFormat;
    private EventBodyBuilder eventBodyBuilder;

    /**
     * Initialize HttpEventCollectorSender
     * @param Url http event collector input server
     * @param token application token
     * @param delay batching delay
     * @param maxEventsBatchCount max number of events in a batch
     * @param maxEventsBatchSize max size of batch
     * @param metadata events metadata
     * @param channel unique GUID for the client to send raw events to the server
     * @param type event data type
     */
    public HttpEventCollectorSender(
            final String Url, final String token, final String channel, final String type,
            long delay, long maxEventsBatchCount, long maxEventsBatchSize,
            String sendModeStr,
            Dictionary<String, String> metadata) {
        this.url = Url;
        this.token = token;
        this.channel = channel;
        this.type = type;

        if ("Raw".equalsIgnoreCase(type)) {
            this.url = Url + HttpRawCollectorUriPath;
        }

        // when size configuration setting is missing it's treated as "infinity",
        // i.e., any value is accepted.
        if (maxEventsBatchCount == 0 && maxEventsBatchSize > 0) {
            maxEventsBatchCount = Long.MAX_VALUE;
        } else if (maxEventsBatchSize == 0 && maxEventsBatchCount > 0) {
            maxEventsBatchSize = Long.MAX_VALUE;
        }
        this.maxEventsBatchCount = maxEventsBatchCount;
        this.maxEventsBatchSize = maxEventsBatchSize;
        this.metadata = metadata;

        final String format = metadata.get(MetadataMessageFormatTag);
        // Get MessageFormat enum from format string. Do this once per instance in constructor to avoid expensive operation in
        // each event sender call
        this.messageFormat = MessageFormat.fromFormat(format);

        if (sendModeStr != null) {
            if (sendModeStr.equals(SendModeSequential))
                this.sendMode = SendMode.Sequential;
            else if (sendModeStr.equals(SendModeSParallel))
                this.sendMode = SendMode.Parallel;
            else
                throw new IllegalArgumentException("Unknown send mode: " + sendModeStr);
        }

        if (delay > 0) {
            // start heartbeat timer
            timer = new Timer();
            timer.scheduleAtFixedRate(this, delay, delay);
        }
    }

    public void addMiddleware(HttpEventCollectorMiddleware.HttpSenderMiddleware middleware) {
        this.middleware.add(middleware);
    }

    /**
     * Send a single logging event in case of batching the event isn't sent immediately
     * @param severity event severity level (info, warning, etc.)
     * @param message event text
     */
    public synchronized void send(
            final String severity,
            final String message,
            final String logger_name,
            final String thread_name,
            Map<String, String> properties,
            final String exception_message,
            Serializable marker,
            Object[] arguments
    ) {
        // create event info container and add it to the batch
        HttpEventCollectorEventInfo eventInfo =
                new HttpEventCollectorEventInfo(severity, message, logger_name, thread_name, properties, exception_message, marker,
                        arguments);
        eventsBatch.add(eventInfo);
        eventsBatchSize += severity.length() + message.length();
        if (eventsBatch.size() >= maxEventsBatchCount || eventsBatchSize > maxEventsBatchSize) {
            flush();
        }
    }

    public synchronized void send(
            final String severity,
            final String message,
            final String logger_name,
            final String thread_name,
            Map<String, String> properties,
            final String exception_message,
            Serializable marker
    ) {
        send(severity, message, logger_name, thread_name, properties, exception_message, marker, null);
    }

    /**
     * Send a single logging event with message only in case of batching the event isn't sent immediately
     * @param message event text
     */
    public synchronized void send(final String message) {
        send("", message, "", "", null, null, "");
    }

    /**
     * Flush all pending events
     */
    public synchronized void flush() {
        flush(false);
    }

    public synchronized void flush(boolean close) {
        if (eventsBatch.size() > 0) {
            postEventsAsync(eventsBatch, close);
        }
        // Clear the batch. A new list should be created because events are
        // sending asynchronously and "previous" instance of eventsBatch object
        // is still in use.
        eventsBatch = new LinkedList<HttpEventCollectorEventInfo>();
        eventsBatchSize = 0;
    }

    /**
     * Close events sender
     */
    void close() {
        if (timer != null)
            timer.cancel();
        flush(true);
        super.cancel();
    }

    /**
     * Timer heartbeat
     */
    @Override // TimerTask
    public void run() {
        flush();
    }

    /**
     * Disable https certificate validation of the splunk server.
     * This functionality is for development purpose only.
     */
    public void disableCertificateValidation() {
        disableCertificateValidation = true;
    }

    public void setEventBodyBuilder(EventBodyBuilder eventBodyBuilder) {
        this.eventBodyBuilder = eventBodyBuilder;
    }

    @SuppressWarnings("unchecked")
    public static void putIfPresent(JSONObject collection, String tag, Object value) {
        if (value != null) {
            if (value instanceof String && ((String) value).length() == 0) {
                // Do not add blank string
                return;
            }
            collection.put(tag, value);
        }
    }

    @SuppressWarnings("unchecked")
    private String serializeEventInfo(HttpEventCollectorEventInfo eventInfo) {
        // create event json content
        //
        // cf: http://dev.splunk.com/view/event-collector/SP-CAAAE6P
        //
        JSONObject event = new JSONObject();
        // event timestamp and metadata
        putIfPresent(event, MetadataTimeTag, String.format(Locale.US, "%.3f", eventInfo.getTime()));
        putIfPresent(event, MetadataHostTag, metadata.get(MetadataHostTag));
        putIfPresent(event, MetadataIndexTag, metadata.get(MetadataIndexTag));
        putIfPresent(event, MetadataSourceTag, metadata.get(MetadataSourceTag));
        putIfPresent(event, MetadataSourceTypeTag, metadata.get(MetadataSourceTypeTag));

        // Parse message on the basis of format
        final Object parsedMessage = this.messageFormat.parse(eventInfo.getMessage());

        if (eventBodyBuilder == null) {
            eventBodyBuilder = new EventBodyBuilder.Default();
        }

        event.put("event", eventBodyBuilder.buildEventBody(eventInfo, parsedMessage));
        return event.toString();
    }

    private synchronized void initHttpClient() {
        if (httpClient != null) {
            // http client is already initialized
            return;
        }

        OkHttpClient.Builder clientBuilder = new OkHttpClient.Builder();

        // limit max  number of concurrent requests in sequential mode
        if (sendMode == SendMode.Sequential) {
            Dispatcher dispatcher = new Dispatcher();
            dispatcher.setMaxRequests(1);
            dispatcher.setMaxRequestsPerHost(1);

            clientBuilder.dispatcher(dispatcher);
        }

        if (disableCertificateValidation) {
            setAllowAllStrategy(clientBuilder);
        }

        httpClient = clientBuilder.build();
    }

    private OkHttpClient.Builder setAllowAllStrategy(OkHttpClient.Builder builder) {
        final TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType) {
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] chain, String authType) {
                    }

                    @Override
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[]{};
                    }
                }
        };

        SSLContext trustAllSslContext;
        try {
            trustAllSslContext = SSLContext.getInstance("SSL");
            trustAllSslContext.init(null, trustAllCerts, new java.security.SecureRandom());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (KeyManagementException e) {
            throw new RuntimeException(e);
        }

        return builder
                .sslSocketFactory(trustAllSslContext.getSocketFactory(), (X509TrustManager)trustAllCerts[0])
                .hostnameVerifier(new HostnameVerifier() {
                    @Override
                    public boolean verify(String hostname, SSLSession session) {
                        return true;
                    }
                });

    }

    private void postEventsAsync(final List<HttpEventCollectorEventInfo> events, final boolean close) {
        final HttpEventCollectorSender sender = this;
        this.middleware.postEvents(events,  this, new HttpEventCollectorMiddleware.IHttpSenderCallback() {

            @Override
            public void completed(int statusCode, String reply) {
                if (statusCode != 200) {
                    HttpEventCollectorErrorHandler.error(
                            events,
                            new HttpEventCollectorErrorHandler.ServerErrorException(reply));
                }
            }

            @Override
            public void failed(Exception ex) {
                HttpEventCollectorErrorHandler.error(
                        eventsBatch,
                        new HttpEventCollectorErrorHandler.ServerErrorException(ex.getMessage()));
            }
        });
    }

    public void postEvents(final List<HttpEventCollectorEventInfo> events,
                           final HttpEventCollectorMiddleware.IHttpSenderCallback callback) {

        initHttpClient();

        // convert events list into a string
        StringBuilder eventsBatchString = new StringBuilder();
        for (HttpEventCollectorEventInfo eventInfo : events)
            eventsBatchString.append(serializeEventInfo(eventInfo));

        Headers.Builder headers = new Headers.Builder()
                .add(AuthorizationHeaderTag, String.format(AuthorizationHeaderScheme, token));
        if ("Raw".equalsIgnoreCase(type) && channel != null && !channel.trim().equals("")) {
            headers.add(SPLUNKREQUESTCHANNELTag, channel);
        }

        MediaType JSON = MediaType.get("application/json; charset=utf-8");
        RequestBody body = RequestBody.create(JSON, eventsBatchString.toString());

        Request httpPost = new Request.Builder()
                .url(url)
                .post(body)
                .headers(headers.build())
                .build();

        httpClient.newCall(httpPost).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                callback.failed(e);
            }

            @Override
            public void onResponse(Call call, Response response) {
                String reply = "";
                int httpStatusCode = response.code();
                // read reply only in case of a server error
                if (httpStatusCode != 200) {
                    try {
                        reply = response.body().string();
                    } catch (IOException e) {
                        reply = e.getMessage();
                    }
                }
                callback.completed(httpStatusCode, reply);
            }
        });
    }

}
