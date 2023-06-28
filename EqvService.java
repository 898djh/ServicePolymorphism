package com.example.jni222;
import android.app.DownloadManager;
import android.util.Log;

import java.io.*;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

import okhttp3.FormBody;
import okhttp3.Headers;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class EqvService extends Thread{

    public String service_name;
    public String token;
    public String method; // GET or POST
    public String service_url;
    public String dns_url;
    public String host_name;
    public String response_str;
    public String hash_url;
    public  int responseCode;

    public double cost;
    public double loc;
    public double lambda;

    public int wsId;

    public Request request;

    private final Lock _mutex = new ReentrantLock(true);

    outputFunc process_output;

    public void resetExecParam(String url_with_ip, double avg_latency, double std_latency, String hash_url){
        this.service_url = url_with_ip;
        this.loc = avg_latency;
        this.lambda = std_latency;
        this.hash_url = hash_url;
    }

    public void setWsID(int wsId){
        this.wsId = wsId;
    }

    public EqvService(String name, String token, double cost){
        this.service_name = name;
        this.token = token;
        this.cost = cost;
    }

    // child inhenrent and override this function depending on each specific function
    // args: city_name
    public void connectInput(inputFunc query, String... args) throws IOException {

        this.request = query.run1(args);
//            this.service_url = this.httpConn.getURL().getQuery();

        this.request.url();


        this.service_url = this.request.url().toString();;
        this.host_name = this.request.url().host();

        if (this.request.method().equals("GET")){
            String processed = this.service_url;
            for (String arg : args){
                processed = processed.replace(arg, "");
            }
            this.dns_url = processed;
        } else{
            this.dns_url = this.service_url;
        }

    }


    public void run(){
        try {
            this.invoke();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


//    public PloymorphicInvocationRes invoke() throws IOException {
    public void invoke() throws IOException {

        long startTime = System.nanoTime();

//        OkHttpClient client = new OkHttpClient();
//
//        Response response = client.newCall(this.request).execute();

        OkHttpClient.Builder client = new OkHttpClient().newBuilder().hostnameVerifier(new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        });

//        client.build().newCall()

        Response response = client.build().newCall(request).execute();

        this.responseCode = response.code();

//        Log.d("response: ", response.toString());
        if (response.isSuccessful()) { // success
            // Get response headers
//            Headers responseHeaders = response.headers();
//            for (int i = 0; i < responseHeaders.size(); i++) {
//                System.out.println(responseHeaders.name(i) + ": " + responseHeaders.value(i));
//            }

            // Get response body



//            System.out.println(response.body().string());

            this.response_str = response.body().string();
            System.out.println(this.response_str);


        } else {
            System.out.println("GET request not worked, code: " + this.responseCode);
            this.response_str = "error";
        }

        long endTime = System.nanoTime();
        long timeElapsed = (endTime - startTime) / 1000000;

        Log.d("timeElapsed: ", this.host_name + ", " + String.valueOf(timeElapsed));

        _mutex.lock();
        PolymorphicWebService.res_success_list.put(hash_url, new PloymorphicInvocationRes(response_str, responseCode, host_name, hash_url, timeElapsed));
        _mutex.unlock();
//        return new PloymorphicInvocationRes(response_str, responseCode, host_name, hash_url);
    }

    // process, parse result and return result, child class need to override
    public void connectOutput(outputFunc process){
        this.process_output = process;
    }

    public String[] execute_praseOutput(){
        return this.process_output.run2(this.response_str);
    }

}
