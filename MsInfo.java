package com.example.jni222;

public class MsInfo{
    String IP;
    double cost;
    double latency;
    double reliability;
    String hostname;
    String newURL;

    public MsInfo() {

    }


    public void setInfo(String ip, double c, double l, double r, String hostname) {
        this.IP = ip;
        this.cost = c;
        this.latency = l;
        this.reliability = r;
        this.hostname = hostname;
        this.newURL = "";
    }


}
