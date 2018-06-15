package com.egguncle.mismatchparcel.util;

import android.os.Parcel;

import java.io.FileOutputStream;

/**
 * Created by songyucheng on 18-6-14.
 */

public class MyFileUtil {

    public static void dumpBundle(Parcel parcel, String name) {
        byte[] data = parcel.marshall();
        try {
            FileOutputStream fileOutputStream = new FileOutputStream("/sdcard/" + name + ".data");
            fileOutputStream.write(data);
            fileOutputStream.close();
        } catch (Exception e) {

        }
    }

}
