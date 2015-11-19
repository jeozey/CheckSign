package com.jeo.checksign;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = MainActivity.class.getName();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        try {
            List<String> str = getSignaturesFromApk(new File("/sdcard/com.rj.apk"));
            Log.e(TAG, "str:" + str.get(0));
            List<String> str1 = getSignaturesFromApk(new File("/sdcard/unsigned.apk"));
            Log.e(TAG, "str1:" + str1.get(0));
        } catch (Exception e) {
            e.printStackTrace();
        }
//        getSign(getBaseContext(), getPackageName());
        getSign(getBaseContext(), "com.jeo.imagebrowser");

//        getSingInfo("com.rj");
//        getSingInfo("com.jeo.imagebrowser");
    }


    public void getSingInfo(String pkgName) {
        try {
            PackageInfo packageInfo = getPackageManager().getPackageInfo(pkgName, PackageManager.GET_SIGNATURES);
            android.content.pm.Signature[] signs = packageInfo.signatures;
            android.content.pm.Signature sign = signs[0];
            parseSignature(sign.toByteArray());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void parseSignature(byte[] signature) {
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(signature));
            String pubKey = cert.getPublicKey().toString();
            String signNumber = cert.getSerialNumber().toString();
            Log.e(TAG, "signName:" + cert.getSigAlgName());
            Log.e(TAG, "pubKey:" + pubKey);
            Log.e(TAG, "signNumber:" + signNumber);
            Log.e(TAG, "subjectDN:" + cert.getSubjectDN().toString());
        } catch (CertificateException e) {
            e.printStackTrace();
        }
    }

   /* 某些时候需要获取某个特定的apk(已安装或者未安装)的签名信息,如程序自检测,可信赖的第三方检测（应用市场）,系统限定安装
    对此，有两种实现方法
       可以使用Java自带的API(主要用到的为JarFile,JarEntry,Certificate)进行获取,还有一种方法是使用系统隐藏的API PackageParser,通过反射来使用对应的API.
    但是由于安卓系统的分裂版本过多，并且不同厂商进行的修改很多，依赖反射隐藏API的方法并不能保证兼容性和通用性，因此推荐使用JAVA自带API进行获取：*/

    /**
     * 从APK中读取签名
     *
     * @param file
     * @return
     * @throws IOException
     */
    private static List<String> getSignaturesFromApk(File file) throws IOException {
        List<String> signatures = new ArrayList<String>();
        JarFile jarFile = new JarFile(file);
        try {
            JarEntry je = jarFile.getJarEntry("AndroidManifest.xml");
            byte[] readBuffer = new byte[8192];
            Certificate[] certs = loadCertificates(jarFile, je, readBuffer);
            if (certs != null) {
                for (Certificate c : certs) {
                    String sig = toCharsString(c.getEncoded());
                    signatures.add(sig);
                }
            }
        } catch (Exception ex) {
        }
        return signatures;
    }


    /**
     * 加载签名
     *
     * @param jarFile
     * @param je
     * @param readBuffer
     * @return
     */
    private static Certificate[] loadCertificates(JarFile jarFile, JarEntry je, byte[] readBuffer) {
        try {
            InputStream is = jarFile.getInputStream(je);
            while (is.read(readBuffer, 0, readBuffer.length) != -1) {
            }
            is.close();
            return je != null ? je.getCertificates() : null;
        } catch (IOException e) {
        }
        return null;
    }


    /**
     * 将签名转成转成可见字符串
     *
     * @param sigBytes
     * @return
     */
    private static String toCharsString(byte[] sigBytes) {
        byte[] sig = sigBytes;
        final int N = sig.length;
        final int N2 = N * 2;
        char[] text = new char[N2];
        for (int j = 0; j < N; j++) {
            byte v = sig[j];
            int d = (v >> 4) & 0xf;
            text[j * 2] = (char) (d >= 10 ? ('a' + d - 10) : ('0' + d));
            d = v & 0xf;
            text[j * 2 + 1] = (char) (d >= 10 ? ('a' + d - 10) : ('0' + d));
        }
        return new String(text);
    }

    private String getSign(Context context, String pkgName) {
        PackageManager pm = context.getPackageManager();
        List<PackageInfo> apps = pm.getInstalledPackages(PackageManager.GET_SIGNATURES);
        Iterator<PackageInfo> iter = apps.iterator();
        while (iter.hasNext()) {
            PackageInfo packageinfo = iter.next();
            String packageName = packageinfo.packageName;
            if (packageName.equals(pkgName)) {
                Log.e(TAG, packageinfo.signatures[0].toCharsString());

                return packageinfo.signatures[0].toCharsString();
            }
        }
        return null;
    }
}
