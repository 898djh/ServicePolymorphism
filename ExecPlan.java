package com.example.jni222;


import android.util.Log;

import java.net.HttpURLConnection;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

enum ExecPlanTypes
{
    //Microservice, Sequential, Speculative Parallel
    equBranch, SEQ, spePAR;
}

public class ExecPlan {
    public static double  executionCost=0;
    public static int succeedCounter=0;
    public ExecPlanTypes type;
//    private ExecutorService executor = Executors.newSingleThreadExecutor();
    private ExecutorService executor = Executors.newFixedThreadPool(3);

    public void initStatusCounter() {
        executionCost = 0;
        succeedCounter = 0;
    }


    public Future<PloymorphicInvocationRes> execute(String serviceInput, executionStatus exe_status) {
        if(this.type==ExecPlanTypes.equBranch) {

            return  executor.submit(  () -> {
                Leaf tmp = (Leaf)this;
                long startTime = System.nanoTime();

                //execute each EquMS
//                PloymorphicInvocationRes ret = tmp.branch.invoke();
                PloymorphicInvocationRes ret = null;
                long endTime = System.nanoTime();
                long timeElapsed = (endTime - startTime)/1000000;
                ExecPlan.executionCost += tmp.branch.cost;
                ret.reporting_latency = (int) timeElapsed;
                Log.d("", ret.host_name + ": " + ret.reporting_latency);
                return ret;

            });
        }else {
            return executor.submit(() -> {
                Par tmp = (Par)this;
                List<Future<PloymorphicInvocationRes>> futures = new ArrayList<Future<PloymorphicInvocationRes>>();
                for(ExecPlan cp: tmp.children) {
                    Future<PloymorphicInvocationRes> cpF = cp.execute(serviceInput, exe_status);
                    futures.add(cpF);
                }

                PloymorphicInvocationRes rt = null;
//                List<PloymorphicInvocationRes> res_success = new ArrayList<>();
                Map<String, PloymorphicInvocationRes> res_success = new HashMap<String, PloymorphicInvocationRes>();

                while(true) {

                    int unfinishedThreads = futures.size();

                    for(Future<PloymorphicInvocationRes> f:futures) {
                        if(f.isDone()) {
                            unfinishedThreads--;
                            rt = f.get();
                            if (rt.response_code == HttpURLConnection.HTTP_OK){
                                res_success.put(rt.hash_url, rt);
                                PolymorphicWebService.res_success_list.put(rt.hash_url, rt);
                            }
                        }
                    }

                    if(unfinishedThreads==0) { // all services completed
                        break;
                    }
                }

                for (Map.Entry<String, PloymorphicInvocationRes> res : res_success.entrySet()){

//                    Log.d("reporting_latency: ", String.valueOf(res.getValue().reporting_latency));
//                    AsyncDnsQos.ReportQoS(res.getValue().hash_url, res.getValue().reporting_latency);
                    PolymorphicWebService.rep_exec_list.add(res.getValue());
                }

                return rt;
            });
        }
    }



}

class Leaf extends ExecPlan{
    public EqvService branch;
    public Leaf(EqvService b) {
        super();
        this.type = ExecPlanTypes.equBranch;
        branch = b;
    }
}

class Seq extends ExecPlan{
    public ExecPlan left;
    public ExecPlan right;
    public Seq() {
        super();
        this.type = ExecPlanTypes.SEQ;
    }
    public Seq(ExecPlan l, ExecPlan r) {
        super();
        this.type = ExecPlanTypes.SEQ;
        this.setLeft(l);
        this.setRight(r);
    }

    public void setLeft(ExecPlan l) {
        this.left = l;
    }
    public ExecPlan getLeft() {
        return this.left;
    }
    public void setRight(ExecPlan r) {
        this.right = r;
    }
    public ExecPlan getRight() {
        return this.right;
    }
}

class Par extends ExecPlan {
    public List<ExecPlan> children = new ArrayList<ExecPlan>();

    public Par() {
        super();
        this.type = ExecPlanTypes.spePAR;
    }

    public Par(List<ExecPlan> c) {
        super();
        this.type = ExecPlanTypes.spePAR;
        children = c;
    }

    public void append(ExecPlan c) {
        children.add(c);
    }
}