package com.egguncle.mismatchparcel.data;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * Created by songyucheng on 18-6-13.
 */

public class EvilParcel implements Parcelable {

    private String evilData;

    public String getEvilData() {
        return evilData;
    }

    public EvilParcel(String str) {
        evilData = str;
    }

    protected EvilParcel(Parcel in) {
        readFromParcel(in);
    }

    public static final Creator<EvilParcel> CREATOR = new Creator<EvilParcel>() {
        @Override
        public EvilParcel createFromParcel(Parcel in) {
            return new EvilParcel(in);
        }

        @Override
        public EvilParcel[] newArray(int size) {
            return new EvilParcel[size];
        }
    };

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel parcel, int i) {
        parcel.writeString(evilData);
    }

    public void readFromParcel(Parcel in) {
        evilData = in.readString();
    }
}
