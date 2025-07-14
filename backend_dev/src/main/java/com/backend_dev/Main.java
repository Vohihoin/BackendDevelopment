package com.backend_dev;


import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.env.BasicIniEnvironment;
import org.apache.shiro.env.Environment;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Main {


    public static final transient Logger log = LoggerFactory.getLogger(Main.class);
    public static void main(String[] args) {
        log.info("My First Shiro App. Cool beans!");
        Environment env = new BasicIniEnvironment("classpath:shiro.ini");
        SecurityManager securityManager = env.getSecurityManager();
        SecurityUtils.setSecurityManager(securityManager);

        Subject currentUser = SecurityUtils.getSubject();
        currentUser.getSession();
        if (!currentUser.isAuthenticated()){
            UsernamePasswordToken token = new UsernamePasswordToken("root","secret");
            token.setRememberMe(true);
            try{
                currentUser.login(token);
            }catch(AuthenticationException e){

            }
            
        }
    

        System.exit(0);
    }
}