package com.myelindata.RSAStuff;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args ) throws Exception
    {
    	
    	Path pubPath = Paths.get("/Users/briang/git/RSAStuff/src/main/resources/public.key");
    	
    	Path privPath = Paths.get("/Users/briang/git/RSAStuff/src/main/resources/private.key");
    	
        RSAPublicKey pub1 = readPublicKey( pubPath.toFile()) ;
        RSAPublicKey pub2 = readPublicKeyBouncy( pubPath.toFile() ) ;
        RSAPublicKey pub3 = readPublicKeySecondApproach( pubPath.toFile() );
        

        
        assert pub1.equals(pub2) && pub2.equals(pub3);
        
//        RSAPrivateKey priv1 = readPrivateKey(privPath.toFile());
//        RSAPrivateKey priv2 = readPrivateKeyBouncy(privPath.toFile());
//        RSAPrivateKey priv3 = readPrivateKeySecondApproach(privPath.toFile());
        RSAPrivateKey priv4 = readPrivateKeySecondApproachForOpenSSLStyle(privPath.toFile());
        
//        assert priv2.equals(priv3);
        
        System.out.println(pub1);
        System.out.println(pub2);
        System.out.println(pub3);
//        System.out.println(priv1);
//        System.out.println(priv2);
//        System.out.println(priv3);
        System.out.println(priv4);
    }
    
    
    public static RSAPublicKey readPublicKey(File file) throws Exception {
        String key = new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());

        String publicKeyPEM = key
          .replace("-----BEGIN PUBLIC KEY-----", "")
          .replaceAll(System.lineSeparator(), "")
          .replace("-----END PUBLIC KEY-----", "");

        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }
    
    public static RSAPublicKey readPublicKeyBouncy(File file) throws Exception {
        KeyFactory factory = KeyFactory.getInstance("RSA");

        try (FileReader keyReader = new FileReader(file);
          PemReader pemReader = new PemReader(keyReader)) {

            PemObject pemObject = pemReader.readPemObject();
            byte[] content = pemObject.getContent();
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
            return (RSAPublicKey) factory.generatePublic(pubKeySpec);
        }
    }
    
    public static RSAPublicKey readPublicKeySecondApproach(File file) throws IOException {
        try (FileReader keyReader = new FileReader(file)) {
            PEMParser pemParser = new PEMParser(keyReader);
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(pemParser.readObject());
            return (RSAPublicKey) converter.getPublicKey(publicKeyInfo);
        }
    }
    
    
    public static RSAPrivateKey readPrivateKey(File file) throws Exception {
        String key = new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());

        String privateKeyPEM = key
          .replace("-----BEGIN RSA PRIVATE KEY-----", "")
          .replaceAll(System.lineSeparator(), "")
          .replace("-----END RSA PRIVATE KEY-----", "");

        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }
    
    public static RSAPrivateKey readPrivateKeyBouncy(File file) throws Exception {
        KeyFactory factory = KeyFactory.getInstance("RSA");

        try (FileReader keyReader = new FileReader(file);
          PemReader pemReader = new PemReader(keyReader)) {

            PemObject pemObject = pemReader.readPemObject();
            byte[] content = pemObject.getContent();
            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
            return (RSAPrivateKey) factory.generatePrivate(privKeySpec);
        }
    }
    
    public static RSAPrivateKey readPrivateKeySecondApproach(File file) throws IOException {
        try (FileReader keyReader = new FileReader(file)) {

            PEMParser pemParser = new PEMParser(keyReader);
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(pemParser.readObject());
            

            return (RSAPrivateKey) converter.getPrivateKey(privateKeyInfo);
        }
    }
    
    public static RSAPrivateKey readPrivateKeySecondApproachForOpenSSLStyle(File file) throws IOException {
        try (FileReader keyReader = new FileReader(file)) {

            PEMParser pemParser = new PEMParser(keyReader);
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
//            PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(pemParser.readObject());
            
            PemObject pemObj = pemParser.readPemObject();
            PrivateKeyInfo privateKeyInfo =  new PrivateKeyInfo(new 
            		AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE), 
            		org.bouncycastle.asn1.pkcs.RSAPrivateKey.getInstance( pemObj.getContent())); 
            

            return (RSAPrivateKey) converter.getPrivateKey(privateKeyInfo);
        }
        
    }
    
    
    
    
}
