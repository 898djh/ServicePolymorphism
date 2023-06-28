package com.example.jni222;

public class PloymorphicInvocationRes {

    public String response;
    public String host_name;
//    public int wsId;
    public int response_code;

    public long reporting_latency;
    public String service_url;
    public String hash_url;

    public PloymorphicInvocationRes(String response, int response_code, String host_name, String hash_url, long reporting_latency){
        this.response = response;
        this.response_code = response_code;
//        this.wsId = wsId;
        this.host_name = host_name;
        this.hash_url = hash_url;
        this.reporting_latency = reporting_latency;
    }
}
