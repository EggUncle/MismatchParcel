package com.egguncle.mismatchparcel.data;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * Created by songyucheng on 18-6-12.
 */

public class MyMismatchParcel implements Parcelable {

    private final static String TAG="MYTEST_MyMismatchParcel";

    private int mDataInt;

    public int getmDataInt() {
        return mDataInt;
    }

    protected MyMismatchParcel(Parcel in) {
        readFromParcel(in);
    }

    public static final Creator<MyMismatchParcel> CREATOR = new Creator<MyMismatchParcel>() {
        @Override
        public MyMismatchParcel createFromParcel(Parcel in) {
            return new MyMismatchParcel(in);
        }

        @Override
        public MyMismatchParcel[] newArray(int size) {
            return new MyMismatchParcel[size];
        }
    };

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel parcel, int i) {
        parcel.writeLong(mDataInt);
    }

    public void readFromParcel(Parcel in) {
        mDataInt = in.readInt();
    }
}
