package com.example.jni222;

public class PlanQoS{
    public String executionPlan;
    public double cost;
    public double latency;
    public double reliability;

    public PlanQoS(String plan, double c, double l, double r) {
        this.executionPlan = plan;
        this.cost = c;
        this.latency = l;
        this.reliability = r;
    }
}
