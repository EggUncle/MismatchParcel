package com.egguncle.mismatchparcel.ui;

import android.os.Bundle;
import android.os.Parcel;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;

import com.egguncle.mismatchparcel.R;
import com.egguncle.mismatchparcel.data.EvilParcel;
import com.egguncle.mismatchparcel.data.MyMismatchParcel;
import com.egguncle.mismatchparcel.util.MyFileUtil;


public class Main2Activity extends AppCompatActivity {

    private final static String TAG = "MYTEST2";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main2);

        findViewById(R.id.btn_2).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Bundle bundle = getIntent().getExtras();
                if (bundle != null) {
                    Parcel parcel = Parcel.obtain();
                    bundle.writeToParcel(parcel, 0);
                    MyFileUtil.dumpBundle(parcel, "test2");
                    MyMismatchParcel myMismatchParcel = bundle.getParcelable("mytest");
                    if (myMismatchParcel != null) {
                        Log.i(TAG, "onClick: " + myMismatchParcel.getmDataInt());
                    } else {
                        Log.i(TAG, "onClick: mytest is null");
                    }
                    if (bundle.getParcelable("evilkv") != null) {
                        Log.i(TAG, "onClick: evilkv is not null");
                        EvilParcel evilParcel=bundle.getParcelable("evilkv");
                        Log.i(TAG, "onClick: "+evilParcel.getEvilData());
                    } else {
                        Log.i(TAG, "onClick: evilkv is null");
                    }
                    Long testLong=bundle.getLong("");
                    Log.i(TAG, "onClick: "+testLong);

                } else {
                    Log.i(TAG, "onCreate: bundle is null");
                }

            }
        });
    }
}
