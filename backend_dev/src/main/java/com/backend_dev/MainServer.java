package com.backend_dev;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.concurrent.Executors;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.env.BasicIniEnvironment;
import org.apache.shiro.env.Environment;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpExchange;

public class MainServer {

    private enum RequestType{
        VERIFY_USER;
    }

    private static SecurityManager securityManager;
    public static final transient Logger log = LoggerFactory.getLogger(MainServer.class);
    public static void main(String[] args) throws IOException{

        log.info("First log");
        configureSecurityManger();
        log.info("Second log");

        HttpServer server = HttpServer.create(new InetSocketAddress(80), 0);
        HttpContext mainContext = server.createContext("/hospital/");
        server.setExecutor(Executors.newCachedThreadPool());
        mainContext.setHandler(MainServer::handle);

        log.info("Starting Server");
        server.start();

    }

    /**
     * Configures the SecurityManager at startup
     */
    public static void configureSecurityManger(){
        Environment env = new BasicIniEnvironment("classpath:shiro.ini");
        securityManager = env.getSecurityManager();
        SecurityUtils.setSecurityManager(securityManager);
    }

    public static void handle(HttpExchange exchange) throws IOException{

        log.info("Request received");

        // GET REQUEST TYPE
        RequestType requestType = getRequestType(exchange.getRequestURI().getPath());
        if (requestType == null){
            System.out.println("Improper Request Type");
            exchange.sendResponseHeaders(404, "Improper Request Type".length());
            exchange.getResponseBody().write("Improper Request Type".getBytes());
            exchange.close();
            return;
        }

        // GET PARAMETERS
        String queryString = exchange.getRequestURI().getQuery();
        String[] keyValuePairs = queryString.split("&");

        HashMap<String,String> parameterMap = new HashMap<>();
        for (int i = 0; i < keyValuePairs.length; i++){
            String[] tokens = keyValuePairs[i].split("=");
            if (tokens.length == 2){ // we should only have two tokens when we split by 2
                parameterMap.put(tokens[0], inputValidate(tokens[1]));
            }
        }

        switch(requestType){

            case VERIFY_USER:
                if (verifyUser(parameterMap, exchange) != null){
                    exchange.sendResponseHeaders(200, "GOOD".length());
                    exchange.getResponseBody().write("GOOD".getBytes());
                    exchange.close();
                }
                break;
            default:
                System.out.println("Cool");
                break;

        }  


        log.info("Request processed");

    }

    public static Subject verifyUser(HashMap<String, String> inputs, HttpExchange exchange) throws IOException{
        Subject currentUser = SecurityUtils.getSubject();
        String username = inputs.get("username");
        String password = inputs.get("password");
        if (username == null || password == null){
            exchange.sendResponseHeaders(401, "Provide username and password".length());
            exchange.getResponseBody().write("Provide username and password".getBytes());
            exchange.close();
            return null;
        }

        try{
            currentUser.login(new UsernamePasswordToken(username, password));
        }catch(AuthenticationException e){
            exchange.sendResponseHeaders(401, "Incorrect Login Details".length());
            exchange.getResponseBody().write("Incorrect Login Details".getBytes());
            exchange.close();
            return null;
        }

        return currentUser;

    }

    public static String inputValidate(String input){
        return input;
    }

    public static RequestType getRequestType(String path){
        if (path.contains("VERIFY_USER")){
            return RequestType.VERIFY_USER;
        }

        return null;
    }
    
}
