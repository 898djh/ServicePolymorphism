//package com.example.jni222;
//
//
//import android.content.Context;
//
//import org.yaml.snakeyaml.Yaml;
//
//import java.io.IOException;
//import java.io.InputStream;
//import java.util.List;
//import java.util.Map;
//
//public class processYAML{
//    @SuppressWarnings("unchecked")
//
//    public static Context mContext;
//
//    public processYAML(Context mContext){
//        this.mContext = mContext;
//    }
//
//    public static Service toService(String id) {
//        Yaml yaml = new Yaml();
//
//
////        InputStream in = new processYAML().getClass().getClassLoader().getResourceAsStream("services/"+id+".yml");
//
//        InputStream in = null;
//        try {
//            assert (mContext != null);
////                in = mContext.getAssets().open(branches.size()+".equ");
//            in = mContext.getAssets().open("services/"+id+".yml");
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//
//
//        Map<String , Object> yamlMaps = (Map<String , Object>)yaml.load(in);
//        List<Map<String , Object>> microservices = (List<Map<String , Object>>)yamlMaps.get("microservices");
//        Microservice[] ms = new Microservice[microservices.size()];
//        int i = 0;
//        for(Map<String , Object> msObj:microservices) {
//            ms[i] = new Microservice((String)msObj.get("id"), (String)msObj.get("input"), (String)msObj.get("output"), (String)msObj.get("url") );
//            i++;
//        }
//        //String id, double cost, double latency, double reliability, String input, String output, Microservice[] ms
//        Service newService = new Service(
//                (String)yamlMaps.get("id"),
//                Double.valueOf((Integer)yamlMaps.get("cost")),
//                Double.valueOf((Integer)yamlMaps.get("latency")),
//                Double.valueOf((Integer)yamlMaps.get("reliability")),
//                (String)yamlMaps.get("input"),
//                (String)yamlMaps.get("output"),
//                ms,
//                mContext
//        );
//        return newService;
//    }
//}
//
