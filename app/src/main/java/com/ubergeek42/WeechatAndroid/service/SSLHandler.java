// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package com.ubergeek42.WeechatAndroid.service;

import android.annotation.SuppressLint;
import android.content.Context;
import android.net.SSLCertificateSocketFactory;
import androidx.annotation.CheckResult;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.ubergeek42.cats.Kitty;
import com.ubergeek42.cats.Root;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class SSLHandler {
    final private static @Root Kitty kitty = Kitty.make();

    private static final String KEYSTORE_PASSWORD = "weechat-android";
    // best-effort RDN regex, matches CN="foo,bar",OU=... and CN=foobar,OU=...
    private static final Pattern RDN_PATTERN = Pattern.compile("CN\\s*=\\s*((?:\"[^\"]*\")|(?:[^\",]*))");

    private File keystoreFile;
    private KeyStore sslKeystore;
    private byte[] clientKeyFile;
    private String clientKeyFilePass;
    private KeyManager[] clientKeyManagers;

    private SSLHandler(File keystoreFile, byte[] clientKeyFile, String clientKeyFilePass) {
        this.keystoreFile = keystoreFile;
        loadKeystore();
        this.clientKeyFile = clientKeyFile;
        this.clientKeyFilePass = clientKeyFilePass;
        loadClientKeyFile();
    }

    private static @Nullable SSLHandler sslHandler = null;

    public static @NonNull SSLHandler getInstance(@NonNull Context context) {
        return getInstance(context, null, "");
    }

    public static @NonNull SSLHandler getInstance(@NonNull Context context, @Nullable byte[] clientKeyFile, @NonNull String clientKeyFilePass) {
        if (sslHandler == null || !sslHandler.sameParameters(clientKeyFile, clientKeyFilePass)) {
            File f = new File(context.getDir("sslDir", Context.MODE_PRIVATE), "keystore.jks");
            sslHandler = new SSLHandler(f, clientKeyFile, clientKeyFilePass);
        }
        return sslHandler;
    }

    private boolean sameParameters(@Nullable byte[] clientKeyFile, @NonNull String clientKeyFilePass) {
        return Arrays.equals(clientKeyFile, this.clientKeyFile) && clientKeyFilePass.equals(this.clientKeyFilePass);
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////

    @SuppressLint("SSLCertificateSocketFactoryGetInsecure")
    public static Result checkHostname(@NonNull String host, int port) {
        final SSLSocketFactory factory = SSLCertificateSocketFactory.getInsecure(0, null);
        SSLSocket ssl = null;
        try {
            ssl = (SSLSocket) factory.createSocket(host, port);
            ssl.startHandshake();
        } catch (IOException e) {
            return new Result(false, ssl == null ? null : getCertificate(ssl));
        }
        SSLSession session = ssl.getSession();
        boolean verified = HttpsURLConnection.getDefaultHostnameVerifier().verify(host, session);
        X509Certificate certificate = getCertificate(ssl);
        try {ssl.close();} catch (IOException ignored) {}
        return new Result(verified, certificate);
    }

    private static @Nullable X509Certificate getCertificate(SSLSocket socket) {
        try {
            return (X509Certificate) socket.getSession().getPeerCertificates()[0];
        } catch (SSLPeerUnverifiedException e) {
            kitty.error("getCertificate()", e);
            return null;
        }
    }

    public static class Result {
        public final @Nullable X509Certificate certificate;
        public final boolean verified;

        Result(boolean verified, @Nullable X509Certificate certificate) {
            this.certificate = certificate;
            this.verified = verified;
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////

    public static Set<String> getCertificateHosts(X509Certificate certificate) {
        final Set<String> hosts = new HashSet<>();
        try {
            final Matcher matcher = RDN_PATTERN.matcher(certificate.getSubjectDN().getName());
            if (matcher.find())
                hosts.add(matcher.group(1));
        } catch (NullPointerException ignored) {}
        try {
            for (List<?> pair : certificate.getSubjectAlternativeNames()) {
                try {
                    hosts.add(pair.get(1).toString());
                } catch (IndexOutOfBoundsException ignored) {}
            }
        } catch(NullPointerException | CertificateParsingException ignored) {}
        return hosts;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////

    public int getUserCertificateCount() {
        try {
            return sslKeystore.size();
        } catch (KeyStoreException e) {
            kitty.error("getUserCertificateCount()", e);
            return 0;
        }
    }

    public void trustCertificate(@NonNull X509Certificate cert) {
        try {
            KeyStore.TrustedCertificateEntry x = new KeyStore.TrustedCertificateEntry(cert);
            sslKeystore.setEntry(cert.getSubjectDN().getName(), x, null);
        } catch (KeyStoreException e) {
            kitty.error("trustCertificate()", e);
        }
        saveKeystore();
    }

    SSLSocketFactory getSSLSocketFactory() {
        SSLCertificateSocketFactory sslSocketFactory = (SSLCertificateSocketFactory) SSLCertificateSocketFactory.getDefault(0, null);
        sslSocketFactory.setKeyManagers(clientKeyManagers);
        sslSocketFactory.setTrustManagers(UserTrustManager.build(sslKeystore));
        return sslSocketFactory;
    }

    // see android.net.SSLCertificateSocketFactory#verifyHostname
    static HostnameVerifier getHostnameVerifier() {
        return HttpsURLConnection.getDefaultHostnameVerifier();
    }

    @CheckResult public boolean removeKeystore() {
        if (keystoreFile.delete()) {
            sslHandler = null;
            return true;
        }
        return false;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////

    // Load our keystore for storing SSL certificates
    private void loadKeystore() {
        try {
            sslKeystore = KeyStore.getInstance("BKS");
            sslKeystore.load(new FileInputStream(keystoreFile), KEYSTORE_PASSWORD.toCharArray());
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            if (e instanceof FileNotFoundException) createKeystore();
            else kitty.error("loadKeystore()", e);
        }
    }

    private void createKeystore() {
        try {
            sslKeystore.load(null, null);
        } catch (Exception e) {
            kitty.error("createKeystore()", e);
        }
        saveKeystore();
    }

    private void saveKeystore() {
        try {
            sslKeystore.store(new FileOutputStream(keystoreFile), KEYSTORE_PASSWORD.toCharArray());
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            kitty.error("saveKeystore()", e);
        }
    }

    private static class UserTrustManager implements X509TrustManager {
        static final X509TrustManager systemTrustManager = buildTrustManger(null);
        private final X509TrustManager userTrustManager;

        private static TrustManager[] build(KeyStore sslKeystore) {
            return new TrustManager[] { new UserTrustManager(sslKeystore) };
        }

        static X509TrustManager buildTrustManger(@Nullable KeyStore store) {
            try {
                TrustManagerFactory tmf =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(store);
                return (X509TrustManager) tmf.getTrustManagers()[0];
            } catch (NoSuchAlgorithmException | KeyStoreException e) {
                return null;
            }
        }

        private UserTrustManager(KeyStore userKeyStore) {
            this.userTrustManager = buildTrustManger(userKeyStore);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s)
            throws CertificateException {
            try {
                systemTrustManager.checkClientTrusted(x509Certificates, s);
                kitty.debug("Client is trusted by system");
            } catch (CertificateException e) {
                kitty.debug("Client is NOT trusted by system, trying user");
                userTrustManager.checkClientTrusted(x509Certificates, s);
                kitty.debug("Client is trusted by user");
            }
        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s)
            throws CertificateException {
            try {
                systemTrustManager.checkServerTrusted(x509Certificates, s);
                kitty.debug("Server is trusted by system");
            } catch (CertificateException e) {
                kitty.debug("Server is NOT trusted by system, trying user");
                userTrustManager.checkServerTrusted(x509Certificates, s);
                kitty.debug("Server is trusted by user");
            }
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            X509Certificate[] system = systemTrustManager.getAcceptedIssuers();
            X509Certificate[] user = userTrustManager.getAcceptedIssuers();
            X509Certificate[] result = Arrays.copyOf(system, system.length + user.length);
            System.arraycopy(user, 0, result, system.length, user.length);
            return result;
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////

    // Load client certificate and private key
    private void loadClientKeyFile() {
        clientKeyManagers = new KeyManager[0];

        if (clientKeyFile != null && clientKeyFile.length > 0) {
            try {
                KeyStore clientKeystore = KeyStore.getInstance("PKCS12");
                clientKeystore.load(new ByteArrayInputStream(clientKeyFile), clientKeyFilePass.toCharArray());

                KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("X509");
                keyManagerFactory.init(clientKeystore, clientKeyFilePass.toCharArray());
                clientKeyManagers = keyManagerFactory.getKeyManagers();
            } catch (KeyStoreException | UnrecoverableKeyException | IOException | NoSuchAlgorithmException | CertificateException | IllegalStateException e) {
                kitty.error("loadClientFile()", e);
            }
        }
    }
}
