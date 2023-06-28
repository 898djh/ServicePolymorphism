package com.example.jni222;

import android.content.Context;
import android.net.ConnectivityManager;
import android.util.Log;

import java.io.IOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.PriorityQueue;
import java.util.TreeMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

enum ExecPattern
{
    Preselected, CostOpt, Balance, LatencyOpt;
}

public class PolymorphicWebService {

    public List<Double> combined_lat_list = new ArrayList<>();

    public Context context;

    public String execPatern;

    public String strategy;

    public String result;

    public String defaultStrategy;

    PloymorphicInvocationRes rep_exec;

    private OkHttpClient client = new OkHttpClient();

    public int probe_flag = 0;
    public int default_flag = 0;


    String probing_strategy;

    public List<EqvService> eqvServiceList = new ArrayList<>();

    public List<EqvService> Probe_eqvServiceList = new ArrayList<>();

    public Map<String, EqvService> eqvServiceMap = new LinkedHashMap<String, EqvService>();

    public Map<Integer, String> eqvServiceNameMap = new LinkedHashMap<Integer, String>();

//    private ExecutorService executor = Executors.newSingleThreadExecutor();

    public static List<PloymorphicInvocationRes> rep_exec_list = new ArrayList<>();

    public static Map<String, PloymorphicInvocationRes> res_success_list = new HashMap<>();
    private final Lock _mutex = new ReentrantLock(true);
    public Map<String, Integer> qos_report = new HashMap<>();

    public int dns_time;

    public float dns_time_c;

    public int status_code;
    public int default_invoke_latency;

    public int running_time;

    static {
        System.loadLibrary("jni222");
    }

    /**
     * A native method that is implemented by the 'jni222' native library,
     * which is packaged with this application.
     */
//    public native String stringFromJNI();


    public static native int initialize_native(ConnectivityManager connectivity_manager);


    public static native String getipbyhostname(String hostname);


    public static native String getiphyhostname_our(String hostname);

    public static native String dnsQueryQoS(String hostnames);

    public static native String dnsQueryQoS_single(String hostnames);



    public static native void ReportQoS(String hash_url, int latency);



    public static void initialize(Context context) {


        initialize_native((ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE));


    }



    public PolymorphicWebService(Context context){
        this.context = context;
    }



    public void addEqvService(EqvService... eqv_services){
        int id = 0;
        for (EqvService eqv : eqv_services){
            this.eqvServiceNameMap.put(id, eqv.host_name);
            eqv.setWsID(id++);
            this.eqvServiceMap.put(eqv.host_name, eqv);
        }

    }


    public void setDefaultStrategy(String str){
        this.defaultStrategy = str;
    }

    // e.g., Preselected, A-B-C
    public void setPattern(String... args){
        if (args.length == 1){
            this.execPatern = args[0];
        } else {
            this.execPatern = args[0];
            this.strategy = args[1];
        }
    }


    public String md5Str(String plaintext) throws NoSuchAlgorithmException {



        MessageDigest m = MessageDigest.getInstance("MD5");
        m.reset();
        m.update(plaintext.getBytes());
        byte[] digest = m.digest();
        BigInteger bigInt = new BigInteger(1,digest);
        String hashtext = bigInt.toString(16);

        while(hashtext.length() < 32 ){
            hashtext = "0"+hashtext;
        }

        return hashtext;
    }

    public void issueDNSQuery2() throws NoSuchAlgorithmException {




        StringBuilder urls_buf = new StringBuilder();
//        int i = 0;
        for (Map.Entry<String, EqvService> item : this.eqvServiceMap.entrySet()){

//            urls_buf.append(hash_urls[i] + item.getValue().host_name);
            urls_buf.append(md5Str(item.getValue().dns_url).toUpperCase() + item.getValue().host_name);



            urls_buf.append(";");
//            i++;
        }

        urls_buf.setLength(urls_buf.length() - 1);



        String urls_str = urls_buf.toString();



        long startTime = System.nanoTime();

        initialize(this.context);
        String dns_ip_qos_result = dnsQueryQoS(urls_str);
//        dnsQueryQoS(urls_str);

        long endTime = System.nanoTime();
        long timeElapsed = (endTime - startTime) / 1000000;
//        Log.d("AsyncDnsQos dns time: ",  String.valueOf(timeElapsed));


        this.dns_time = (int) timeElapsed;


/
        Log.d(" android dns_ip_qos_result: ", dns_ip_qos_result);


//        assert (0 == 1);

        String[] ws = dns_ip_qos_result.split("\\|");




        for (String s : ws){
//            Log.d("ws", s);

            String[] items = s.split("\\$");

            if (items.length == 4){ 
                String hostname = items[0];
                String ip = items[1];
                String[] qos = items[2].split(",");
                double average_latency = Double.parseDouble(qos[0]);
                double tail_latency = Double.parseDouble(qos[1]);

                double less_half_S = Double.parseDouble(qos[2]);
                double larger_half_S = Double.parseDouble(qos[3]);
                double reach_full_S = Double.parseDouble(qos[4]);

                String hash_url = items[3];




                EqvService eqv_ws = eqvServiceMap.get(hostname);
                String eqv_ws_url = eqv_ws.service_url.replaceFirst(hostname, ip);
                eqv_ws.resetExecParam(eqv_ws_url, average_latency, tail_latency, less_half_S, larger_half_S, reach_full_S, hash_url);
            } else if (items.length == 3){ 
                String hostname = items[0];
                String ip = items[1];
                String hash_url = items[2];
                EqvService eqv_ws = eqvServiceMap.get(hostname);
                String eqv_ws_url = eqv_ws.service_url.replaceFirst(hostname, ip);
                eqv_ws.resetExecParam(eqv_ws_url, 0, 0, 0, 0, 0, hash_url);


                this.default_flag++;

            } else if (items.length == 2){ 
                String hostname = items[0];
                String ip = items[1];
                EqvService eqv_ws = eqvServiceMap.get(hostname);
                String eqv_ws_url = eqv_ws.service_url.replaceFirst(hostname, ip);
                eqv_ws.resetExecParam(eqv_ws_url, 0, 0, 0, 0, 0, "");
                this.default_flag++;


            }

        }

        // copy eqvServiceMap to eqvServiceList, it is good for computing strategy
        for (Map.Entry<String, EqvService> item : this.eqvServiceMap.entrySet()){
            eqvServiceList.add(item.getValue());
        }


        for (Map.Entry<String, EqvService> item : this.eqvServiceMap.entrySet()){
            Probe_eqvServiceList.add(item.getValue());
        }

    }




    // Method for getting the minimum value
    public double getMin(double[] inputArray){
        double minValue = inputArray[0];
        for(int i=1;i<inputArray.length;i++){
            if(inputArray[i] < minValue){
                minValue = inputArray[i];
            }
        }
        return minValue;
    }

    //    public ExecPlan calculate_Combination(){
    public String calculate_avg_opt(){

//        System.out.println("===================calculate_avg_opt=======================");



        double less_half_S1 = this.eqvServiceList.get(0).less_half_S;
        double larger_half_S1 = this.eqvServiceList.get(0).larger_half_S;
        double reach_full_S1 = this.eqvServiceList.get(0).reach_full_S;

        double less_half_S2 = this.eqvServiceList.get(1).less_half_S;
        double larger_half_S2 = this.eqvServiceList.get(1).larger_half_S;
        double reach_full_S2 = this.eqvServiceList.get(1).reach_full_S;

        double less_half_S3 = this.eqvServiceList.get(2).less_half_S;
        double larger_half_S3 = this.eqvServiceList.get(2).larger_half_S;
        double reach_full_S3 = this.eqvServiceList.get(2).reach_full_S;


        if (less_half_S1 == 1 && less_half_S2 == 1 && less_half_S3 == 1){ 
            this.default_flag = 1;
            return this.defaultStrategy;
        } else if(reach_full_S1 == 1 && reach_full_S2 == 1 && reach_full_S3 == 1){
            // choose the service with best average latency

            if (this.eqvServiceList.get(0).average_latency <= this.eqvServiceList.get(1).average_latency &&
                    this.eqvServiceList.get(0).average_latency <= this.eqvServiceList.get(2).average_latency){

                return "0";
            } else if (this.eqvServiceList.get(1).average_latency <= this.eqvServiceList.get(0).average_latency &&
                    this.eqvServiceList.get(1).average_latency <= this.eqvServiceList.get(2).average_latency){
                return "1";
            } else if(this.eqvServiceList.get(2).average_latency <= this.eqvServiceList.get(0).average_latency &&
                    this.eqvServiceList.get(2).average_latency <= this.eqvServiceList.get(1).average_latency){
                return "2";
            }



        } else if (reach_full_S1 == 1 || reach_full_S2 == 1 || reach_full_S3 == 1){ 



            StringBuilder probing_str = new StringBuilder();
            if (reach_full_S1 != 1){
                probing_str.append("0");
            }

            if (reach_full_S2 != 1){
                probing_str.append("1");
            }

            if (reach_full_S3 != 1){
                probing_str.append("2");
            }


            this.probe_flag = 1;
            this.probing_strategy = probing_str.toString();
            this.default_flag = 1;
            return this.defaultStrategy;
        } else if (larger_half_S1 == 1 || larger_half_S2 == 1 || larger_half_S3 == 1){

            this.probing_strategy = "012";
            this.default_flag = 1;
            this.probe_flag = 1;
            return this.defaultStrategy;
        }


        return this.defaultStrategy;

    }


    public String calculate_tail_opt(){



        double less_half_S1 = this.eqvServiceList.get(0).less_half_S;
        double larger_half_S1 = this.eqvServiceList.get(0).larger_half_S;
        double reach_full_S1 = this.eqvServiceList.get(0).reach_full_S;

        double less_half_S2 = this.eqvServiceList.get(1).less_half_S;
        double larger_half_S2 = this.eqvServiceList.get(1).larger_half_S;
        double reach_full_S2 = this.eqvServiceList.get(1).reach_full_S;

        double less_half_S3 = this.eqvServiceList.get(2).less_half_S;
        double larger_half_S3 = this.eqvServiceList.get(2).larger_half_S;
        double reach_full_S3 = this.eqvServiceList.get(2).reach_full_S;


        if (less_half_S1 == 1 && less_half_S2 == 1 && less_half_S3 == 1){ 
            this.default_flag = 1;
            return this.defaultStrategy;
        } else if(reach_full_S1 == 1 && reach_full_S2 == 1 && reach_full_S3 == 1){


            if (this.eqvServiceList.get(0).tail_latency <= this.eqvServiceList.get(1).tail_latency &&
                    this.eqvServiceList.get(0).tail_latency <= this.eqvServiceList.get(2).tail_latency){

                return "0";
            } else if (this.eqvServiceList.get(1).tail_latency <= this.eqvServiceList.get(0).tail_latency &&
                    this.eqvServiceList.get(1).tail_latency <= this.eqvServiceList.get(2).tail_latency){
                return "1";
            } else if(this.eqvServiceList.get(2).tail_latency <= this.eqvServiceList.get(0).tail_latency &&
                    this.eqvServiceList.get(2).tail_latency <= this.eqvServiceList.get(1).tail_latency){
                return "2";
            }



        } else if (reach_full_S1 == 1 || reach_full_S2 == 1 || reach_full_S3 == 1){ 



//            probing_s
            StringBuilder probing_str = new StringBuilder();
            if (reach_full_S1 != 1){
                probing_str.append("0");
            }

            if (reach_full_S2 != 1){
                probing_str.append("1");
            }

            if (reach_full_S3 != 1){
                probing_str.append("2");
            }


            this.probe_flag = 1;
            this.probing_strategy = probing_str.toString();
            this.default_flag = 1;
            return this.defaultStrategy;
        } else if (larger_half_S1 == 1 || larger_half_S2 == 1 || larger_half_S3 == 1){
            
            this.probing_strategy = "012";
            this.default_flag = 1;
            this.probe_flag = 1;
            return this.defaultStrategy;
        }


        return this.defaultStrategy;

    }


    public String CalculateOptimizeStrategy(){




        switch (this.execPatern) {

            case "CostEffOpt":
                return "012";

            case "AvgLat":

                String res = calculate_avg_opt();
                assert (!res.equals("error"));
                return res;

            case "TailLat":
                String res2 = calculate_tail_opt();
                assert (!res2.equals("error"));
                return res2;

            default: //"Preselected":
                return this.defaultStrategy;
        }

    }

    public void ProbeServices() throws InterruptedException {

//        System.out.println("====================ProbeServices=====================");


//        this.probing_strategy = "012";
        int size_probe = this.probing_strategy.length();


        if (size_probe == 1){
            String idx_ser1 = this.probing_strategy.charAt(0) + "";
            int s_idx1 = Character.getNumericValue(idx_ser1.charAt(0));
            EqvService s1 = this.Probe_eqvServiceList.get(s_idx1);
            Thread thread1 = new Thread(new Runnable() {

                @Override
                public void run() {
                    try  {
                        long startTime = System.nanoTime();


                        Request request = s1.request;

                        OkHttpClient.Builder client = new OkHttpClient().newBuilder().hostnameVerifier(new HostnameVerifier() {
                            @Override
                            public boolean verify(String hostname, SSLSession session) {
                                return true;
                            }
                        });



                        Response response = client.build().newCall(request).execute();

                        long endTime = System.nanoTime();
                        long timeElapsed = (endTime - startTime) / 1000000;

//                        Log.d("timeElapsed: ", s1.host_name + ", " + String.valueOf(timeElapsed));
                        _mutex.lock();
                        qos_report.put(s1.hash_url, (int) timeElapsed);
                        _mutex.unlock();

                        assert response.body() != null;
//                        System.out.println("probing response1: " + response.body().string());

                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            });

            thread1.start();
            try {
                thread1.join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        } else if (size_probe == 2){

            String idx_ser1 = this.probing_strategy.charAt(0) + "";
            int s_idx1 = Character.getNumericValue(idx_ser1.charAt(0));
            EqvService s1 = this.Probe_eqvServiceList.get(s_idx1);

            String idx_ser2 = this.probing_strategy.charAt(1) + "";
            int s_idx2 = Character.getNumericValue(idx_ser2.charAt(0));
            EqvService s2 = this.Probe_eqvServiceList.get(s_idx2);



            Thread thread1 = new Thread(new Runnable() {

                @Override
                public void run() {
                    try  {
                        long startTime = System.nanoTime();
//                        Request request = new Request.Builder()
//                                .url(s1.service_url)
//                                .build();

                        Request request = s1.request;
                        OkHttpClient.Builder client = new OkHttpClient().newBuilder().hostnameVerifier(new HostnameVerifier() {
                            @Override
                            public boolean verify(String hostname, SSLSession session) {
                                return true;
                            }
                        });



                        Response response = client.build().newCall(request).execute();

                        long endTime = System.nanoTime();
                        long timeElapsed = (endTime - startTime) / 1000000;

//                        Log.d("timeElapsed: ", s1.host_name + ", " + String.valueOf(timeElapsed));
                        _mutex.lock();
                        qos_report.put(s1.hash_url, (int) timeElapsed);
                        _mutex.unlock();
                        assert response.body() != null;
//                        System.out.println("probing response1: " + response.body().string());

                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            });


            Thread thread2 = new Thread(new Runnable() {

                @Override
                public void run() {
                    try  {
                        long startTime = System.nanoTime();
//                        Request request = new Request.Builder()
//                                .url(s2.service_url)
//                                .build();

                        Request request = s2.request;
                        OkHttpClient.Builder client = new OkHttpClient().newBuilder().hostnameVerifier(new HostnameVerifier() {
                            @Override
                            public boolean verify(String hostname, SSLSession session) {
                                return true;
                            }
                        });

                        Response response = client.build().newCall(request).execute();

                        long endTime = System.nanoTime();
                        long timeElapsed = (endTime - startTime) / 1000000;

//                        Log.d("timeElapsed: ", s2.host_name + ", " + String.valueOf(timeElapsed));
                        _mutex.lock();
                        qos_report.put(s2.hash_url, (int) timeElapsed);
                        _mutex.unlock();
                        assert response.body() != null;
//                        System.out.println("probing response2: " + response.body().string());

                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            });


            thread1.start();
            thread2.start();
            try {
                thread1.join();
                thread2.join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }


        } else if (size_probe == 3){

            String idx_ser1 = this.probing_strategy.charAt(0) + "";
            int s_idx1 = Character.getNumericValue(idx_ser1.charAt(0));
            EqvService s1 = this.Probe_eqvServiceList.get(s_idx1);

            String idx_ser2 = this.probing_strategy.charAt(1) + "";
            int s_idx2 = Character.getNumericValue(idx_ser2.charAt(0));
            EqvService s2 = this.Probe_eqvServiceList.get(s_idx2);


            String idx_ser3 = this.probing_strategy.charAt(2) + "";
            int s_idx3 = Character.getNumericValue(idx_ser3.charAt(0));
            EqvService s3 = this.Probe_eqvServiceList.get(s_idx3);

            Thread thread1 = new Thread(new Runnable() {

                @Override
                public void run() {
                    try  {
                        long startTime = System.nanoTime();
//                        Request request = new Request.Builder()
//                                .url(s1.service_url)
//                                .build();

//                        System.out.println("url1: " + request.url());
                        Request request = s1.request;
                        OkHttpClient.Builder client = new OkHttpClient().newBuilder().hostnameVerifier(new HostnameVerifier() {
                            @Override
                            public boolean verify(String hostname, SSLSession session) {
                                return true;
                            }
                        });



                        Response response = client.build().newCall(request).execute();

                        long endTime = System.nanoTime();
                        long timeElapsed = (endTime - startTime) / 1000000;

//                        Log.d("timeElapsed: ", s1.host_name + ", " + String.valueOf(timeElapsed));
                        _mutex.lock();
                        qos_report.put(s1.hash_url, (int) timeElapsed);
                        _mutex.unlock();
                        assert response.body() != null;
//                        System.out.println("probing response1: " + response.body().string());

                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            });


            Thread thread2 = new Thread(new Runnable() {

                @Override
                public void run() {
                    try  {
                        long startTime = System.nanoTime();
//                        Request request = new Request.Builder()
//                                .url(s2.service_url)
//                                .build();
//                        System.out.println("url2: " + request.url());
                        Request request = s2.request;
                        OkHttpClient.Builder client = new OkHttpClient().newBuilder().hostnameVerifier(new HostnameVerifier() {
                            @Override
                            public boolean verify(String hostname, SSLSession session) {
                                return true;
                            }
                        });

                        Response response = client.build().newCall(request).execute();

                        long endTime = System.nanoTime();
                        long timeElapsed = (endTime - startTime) / 1000000;
                        _mutex.lock();
                        qos_report.put(s2.hash_url, (int) timeElapsed);
                        _mutex.unlock();
//                        Log.d("timeElapsed: ", s2.host_name + ", " + String.valueOf(timeElapsed));

                        assert response.body() != null;
//                        System.out.println("probing response2: " + response.body().string());

                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            });

            Thread thread3 = new Thread(new Runnable() {

                @Override
                public void run() {
                    try  {
                        long startTime = System.nanoTime();
//                        Request request = new Request.Builder()
//                                .url(s3.service_url)
//                                .build();
                        Request request = s3.request;
//                        System.out.println("url3: " + request.url());
                        OkHttpClient.Builder client = new OkHttpClient().newBuilder().hostnameVerifier(new HostnameVerifier() {
                            @Override
                            public boolean verify(String hostname, SSLSession session) {
                                return true;
                            }
                        });

                        Response response = client.build().newCall(request).execute();

                        long endTime = System.nanoTime();
                        long timeElapsed = (endTime - startTime) / 1000000;

//                        Log.d("timeElapsed: ", s3.host_name + ", " + String.valueOf(timeElapsed));
                        _mutex.lock();
                        qos_report.put(s3.hash_url, (int) timeElapsed);
                        _mutex.unlock();
                        assert response.body() != null;
//                        System.out.println("probing response3: " + response.body().string());

                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            });

            thread1.start();
            thread2.start();
            thread3.start();
            try {
                thread1.join();
                thread2.join();
                thread3.join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }


        }






    }


    public PloymorphicInvocationRes invokeWS() throws  InterruptedException {


        int size_ws = this.strategy.length();


        for (int i = 0; i < size_ws; i++){
            String idx_ser = this.strategy.charAt(i) + "";
            this.eqvServiceList.get(Character.getNumericValue(idx_ser.charAt(0))).start();
        }

        while (true){
            Thread.sleep(1);
//                Log.d("res_success_list.size(): ", String.valueOf(res_success_list.size()));
            if (res_success_list.size() > 0){ // once there is at least one response, we return the results to parse
                this.status_code = res_success_list.entrySet().iterator().next().getValue().response_code;
                return res_success_list.entrySet().iterator().next().getValue();
            }
        }


    }


    public void invokeWS_new() throws  InterruptedException {


        int s_idx1 = Character.getNumericValue(this.strategy.charAt(0));
        EqvService s1 = this.Probe_eqvServiceList.get(s_idx1);


        int s_idx2 = Character.getNumericValue(this.strategy.charAt(0));
        EqvService s2 = this.Probe_eqvServiceList.get(s_idx2);



        int s_idx3 = Character.getNumericValue(this.strategy.charAt(0));
        EqvService s3 = this.Probe_eqvServiceList.get(s_idx3);





        Request request;
        if (this.strategy.equals("0")){
            request = s1.request;
        } else if (this.strategy.equals("1")){
            request = s2.request;
        } else {
            request = s3.request;
        }



        final int[] rep_code = new int[1];
        final int[] rep_latency = new int[1];


        Thread thread1 = new Thread(new Runnable() {

            @Override
            public void run() {
                try  {
                    long startTime = System.nanoTime();



//                    Request request = new Request.Builder()
//                            .url(call_url)
//                            .build();



                    OkHttpClient.Builder client = new OkHttpClient().newBuilder().hostnameVerifier(new HostnameVerifier() {
                        @Override
                        public boolean verify(String hostname, SSLSession session) {
                            return true;
                        }
                    });



                    Response response = client.build().newCall(request).execute();

                    rep_code[0] = response.code();

                    long endTime = System.nanoTime();
                    long timeElapsed = (endTime - startTime) / 1000000;

//                    Log.d("invokeWS_new timeElapsed: ", s1.host_name + ", " + String.valueOf(timeElapsed));

                    rep_latency[0] = (int)timeElapsed;
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });

        thread1.start();
        try {
            thread1.join();

            this.status_code = rep_code[0];
            this.default_invoke_latency = rep_latency[0];
        } catch (InterruptedException e) {
            e.printStackTrace();
        }


    }

    public void exec() throws ExecutionException, InterruptedException, NoSuchAlgorithmException, IOException {


//        long startTime = System.nanoTime();

        // 1. first issue dns to obtain ip and qos
        if (!this.execPatern.equals("Preselected")){
//            long startTime = System.nanoTime();
            issueDNSQuery2();

        } else{
            for (Map.Entry<String, EqvService> item : this.eqvServiceMap.entrySet()){
                eqvServiceList.add(item.getValue());
            }
        }

//        // 2. optimize the invocation strategy
////        this.execStrategy = CalculateOptimizeStrategy();
//
        this.strategy = CalculateOptimizeStrategy();
////
//        Log.d("strategy: ", this.strategy);





        // 3. invoke and processOutput
//        rep_exec = invokeWS();
        invokeWS_new();



    }


    public void ReportQoS() throws InterruptedException {

        Log.d("", "***************begin ReportQoS***************");

        if (dns_time > 200) // this means dns query proces something wrong, we drop this latency, qos
            return;


        if (this.probe_flag != 0){
            for (Map.Entry<String, Integer> item : qos_report.entrySet()){
                ReportQoS(item.getKey(), item.getValue());
                System.out.println("send qos for : " + item.getKey() + ", lat: " + item.getValue());

            }
        } else{

            int s_idx1 = Character.getNumericValue(this.strategy.charAt(0));
            EqvService s1 = this.Probe_eqvServiceList.get(s_idx1);

            int s_idx2 = Character.getNumericValue(this.strategy.charAt(0));
            EqvService s2 = this.Probe_eqvServiceList.get(s_idx2);

            int s_idx3 = Character.getNumericValue(this.strategy.charAt(0));
            EqvService s3 = this.Probe_eqvServiceList.get(s_idx3);

            String hash_url;

            if (this.strategy.equals("0")){
                hash_url = s1.hash_url;
            } else if (this.strategy.equals("1")){
                hash_url = s2.hash_url;
            } else {
                hash_url = s3.hash_url;
            }

            ReportQoS(hash_url, this.default_invoke_latency);
            System.out.println("send qos for : " + hash_url + ", lat: " + this.default_invoke_latency);
        }

        Log.d("", "***************all qos reported***************");


    }

    public String[] GetRes(){

        this.status_code = Objects.requireNonNull(eqvServiceMap.get(rep_exec.host_name)).responseCode;
        return Objects.requireNonNull(eqvServiceMap.get(rep_exec.host_name)).execute_praseOutput();
    }





}
