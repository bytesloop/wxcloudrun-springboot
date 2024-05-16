package com.tencent.wxcloudrun.service;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.context.EditableArm32RegisterContext;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.linux.android.AndroidARMEmulator;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.linux.file.ByteArrayFileIO;
import com.github.unidbg.linux.file.DumpFileIO;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.spi.SyscallHandler;
import com.github.unidbg.unix.UnixSyscallHandler;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import com.sun.jna.Pointer;
import org.springframework.util.ResourceUtils;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

public class TigerTallyService extends AbstractJni implements IOResolver<AndroidFileIO>{
    private final AndroidEmulator emulator;
    private final VM vm;
    private static TigerTallyService myTigerTallyAPI;

    AndroidEmulatorBuilder androidEmulatorBuilder = new AndroidEmulatorBuilder(false) {
        @Override
        public AndroidEmulator build() {
            return new AndroidARMEmulator("com.aihuishou.opt",rootDir,backendFactories) {
                @Override
                protected UnixSyscallHandler createSyscallHandler(SvcMemory svcMemory) {
                    return new PddArmSysCallHand(svcMemory);
                }
            };
        }
    };
    public class PddArmSysCallHand extends com.github.unidbg.linux.ARM32SyscallHandler {
        public PddArmSysCallHand(SvcMemory svcMemory) {
            super(svcMemory);
        }
        @Override
        protected boolean handleUnknownSyscall(Emulator emulator, int NR) {
            switch (NR) {
                case 190:
                    vfork(emulator);
                    return true;
                case 359:
                    pipe2(emulator);
                    return true;
            }

            return super.handleUnknownSyscall(emulator, NR);
        }
        private void vfork(Emulator<?> emulator) {
            EditableArm32RegisterContext context = (EditableArm32RegisterContext) emulator.getContext();
            int childPid = emulator.getPid() + ThreadLocalRandom.current().nextInt(256);
            int r0 = 0;
            r0 = childPid;
            System.out.println("vfork pid=" + r0);
            context.setR0(r0);
        }


        @Override
        protected int pipe2(Emulator<?> emulator) {
            EditableArm32RegisterContext context = (EditableArm32RegisterContext) emulator.getContext();
            Pointer pipefd = context.getPointerArg(0);
            int flags = context.getIntArg(1);
            int write = getMinFd();
            this.fdMap.put(write, new DumpFileIO(write));
            int read = getMinFd();
            String stdout = "2a6dffba-811a-43e5-96ee-638e71784cb7";
            this.fdMap.put(read, new ByteArrayFileIO(0, "pipe2_read_side", stdout.getBytes()));
            pipefd.setInt(0, read);
            pipefd.setInt(4, write);
            System.out.println("pipe2 pipefd=" + pipefd + ", flags=0x" + flags + ", read=" + read + ", write=" + write + ", stdout=" + stdout);
            context.setR0(0);
            return 0;
        }
    }

    private final Module module;
    private final DvmClass ttClass;

    public void destroy() throws IOException {
        emulator.close();
    }

    public TigerTallyService() throws FileNotFoundException {
        String soPath = "classpath:files/libtiger_tally.so";
        String apkPath = "classpath:files/pkt.apk";
        emulator = androidEmulatorBuilder.build();
        SyscallHandler<AndroidFileIO> syscallHandler =
                emulator.getSyscallHandler();
        syscallHandler.setVerbose(true);
        syscallHandler.addIOResolver(this);
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        vm = emulator.createDalvikVM();
        DalvikModule dm = vm.loadLibrary(ResourceUtils.getFile(soPath), true); // 加载so到虚拟内存
        module = dm.getModule(); //获取本SO模块的句柄
        vm.setJni(this);
        vm.setVerbose(false);
        dm.callJNI_OnLoad(emulator);
        ttClass = vm.resolveClass("com/aliyun/TigerTally/t/B");
    }

    // 获取TigerTallyAPI实例
    public static TigerTallyService getInstance() throws FileNotFoundException {
        if(myTigerTallyAPI == null){
            myTigerTallyAPI = new TigerTallyService();
            myTigerTallyAPI.avmpSign("", true);  // 初始化AVMP
        }
        return myTigerTallyAPI;
    }

    public static void main(String[] args) throws FileNotFoundException {
        TigerTallyService tiger = getInstance();  // 获取TigerTally实例
        String wtoken = tiger.avmpSign("{\"categoryId\":1,\"inquiryFrom\":\"quick_inquiry\",\"pricePropertyValueIds\":[3987,2014,33734,12479,2125,2118,2114,2134,13787,13791,14165,36215,6982,2067,2129,12604,2026,9625,13542,2104,2045,13842,2100,2106,19234,2108,2808,3168,5300,6947,6949,9507,11210,20268],\"productId\":121769}", false);  // 调用avmpSign方法
        System.out.println(wtoken);  // 打印wtoken
    }

    void initAVMP() {
        System.out.println("initAVMP");
        DvmObject<?> dvmObject = ttClass.callStaticJniMethodObject(emulator, "genericNt1(ILjava/lang/String;Z)I", 1,"DMPY7rW5x9iAwiixpYVkrlxR6VSBate6nf9ytcpayRE1yuOz6PSeKycP6mE0qpQOAZSgXU6hzo81flyOYrZUQe-T_dy58TdY43Y97vWB8r6_ydQVOJQBxlkRugwihyuPERxXKR4RMM3qbI847eX-CQ==", true);
    }

    void setAccount() {
        System.out.println("setAccount");
        DvmObject<?> dvmObject = ttClass.callStaticJniMethodObject(emulator, "genericNt2(ILjava/lang/String;)I", 1,"11689918");
    }

    public String avmpSign(String requestBody, boolean hasInit) {
        if (hasInit){
            this.setAccount();
            this.initAVMP();
        }
        DvmObject<?> dvmObject = ttClass.callStaticJniMethodObject(emulator, "genericNt3(I[B)Ljava/lang/String;", 1, requestBody.getBytes(StandardCharsets.UTF_8));
        String wtoken = dvmObject.getValue().toString();
        if(wtoken.equals("you must call init first")){
            dvmObject = ttClass.callStaticJniMethodObject(emulator, "genericNt3(I[B)Ljava/lang/String;", 1, requestBody.getBytes(StandardCharsets.UTF_8));
            wtoken = dvmObject.getValue().toString();
        }
        return wtoken;
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature){
            case "android/content/pm/PackageManager->getApplicationInfo(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;":
                String appName = vaList.getObjectArg(0).getValue().toString();
                System.out.println("check app:"+appName);
                return vm.resolveClass("Landroid/content/pm/ApplicationInfo;").newObject(signature);
            case "android/content/pm/PackageManager->getApplicationLabel(Landroid/content/pm/ApplicationInfo;)Ljava/lang/CharSequence;":
                return new StringObject(vm,"java/lang/CharSequence");
            case "android/app/Application->getFilesDir()Ljava/io/File;":
                return vm.resolveClass("java/io/File");
            case "java/lang/Class->getAbsolutePath()Ljava/lang/String;":
                return new StringObject(vm, "/sdcard");
            case "android/app/Application->getPackageName()Ljava/lang/String;":
                return new StringObject(vm, "com.aihuishou.opt");
            case "android/app/Application->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;":
                return vm.resolveClass("android/content/SharedPreferences").newObject(vaList.getObjectArg(0));
            case "android/content/SharedPreferences->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;":
                String str = vaList.getObjectArg(0).getValue().toString();
                String str2 = vaList.getObjectArg(1).getValue().toString();
                if (str.equals("TT_COOKIEID")){
                    System.out.println("TT_COOKIEID");
                    long currentTimeMillis = System.currentTimeMillis();
                    return new StringObject(vm,"^" + currentTimeMillis+"^86400");
                }
                System.out.println(str + "|" + str2);
            case "android/app/Application->getPackageCodePath()Ljava/lang/String;":    // Frida主动调用打印结果 console.log('Package Code Path: ' + Java.use('android.app.ActivityThread').currentApplication().getPackageCodePath())
                return new StringObject(vm,"/data/app/~~qfgveoyDhF8MMhOsx1OQaA==/com.aihuishou.opt-7KjbKcwCG7ycjdj1pMIMyA==/base.apk");
            case "com/aliyun/TigerTally/s/A$AA->en(Ljava/lang/String;)Ljava/lang/String;":
                return new StringObject(vm,"7d73517c114d407e33b896267607fdde"); // 17157650457717ac4834abdc md5值
            case "com/aliyun/TigerTally/s/A$BB->en(Ljava/lang/String;)Ljava/lang/String;":
                return new StringObject(vm,"b5286d51be30479ba0c41e240100f528bef2733b"); // 17157650457717ac4834abdc sha值
            case "java/lang/Class->toByteArray()[B":
                return new ByteArray(vm,signature.getBytes(StandardCharsets.UTF_8));
        }
        return super.callObjectMethodV(vm, dvmObject, signature, vaList);
    }

    public static String randomDeviceModule(){
        String[] arrayList = {"cheeseburger/dumpling", "enchilada", "enchilada", "fajita", "fajita", "guacamoleb", "guacamoleb", "guacamole", "guacamole", "hotdogb", "hotdogb", "hotdog", "hotdog", "instantnoodle & instantnoodlep", "kebab", "kebab", "lemonade", "lemonade", "lemonadep", "lemonadep", "bacon", "oneplus3", "oneplus2", "onyx", "molly", "sprout", "gm9pro_sprout", "GM6_s_sprout", "seed", "seedmtk", "shamrock", "sailfish", "walleye", "taimen", "blueline", "sargo", "bonito", "crosshatch", "flame", "coral", "redfin", "dragon", "marlin", "f1f", "find5", "find7", "N1", "n3", "R11", "R11s", "r5", "r7f", "r7plusf", "r7sf", "R819", "RMX1801", "RMX1851"};
        Random random = new Random();
        String module = arrayList[random.nextInt(arrayList.length)];
        return module;

    }

    public static String randomVersion(){
        Random random = new Random();
        String a = String.valueOf(random.nextInt(5) + 7);
        return a;
    }
    //length用户要求产生字符串的长度
    public static String getRandomString(int length){
        String str="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        Random random=new Random();
        StringBuffer sb=new StringBuffer();
        for(int i=0;i<length;i++){
            int number=random.nextInt(62);
            sb.append(str.charAt(number));
        }
        return sb.toString();
    }

    @Override
    public DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass dvmClass, String signature) {
        switch (signature){
            case "android/os/Build->BRAND:Ljava/lang/String;":
                return new StringObject(vm,"Android");
            case "android/os/Build->MODEL:Ljava/lang/String;":
                return new StringObject(vm,randomDeviceModule());
            case "android/os/Build$VERSION->RELEASE:Ljava/lang/String;":
                return new StringObject(vm,randomVersion());
            case "android/os/Build->DEVICE:Ljava/lang/String;":
                return new StringObject(vm, getRandomString(7));
        }
        return super.getStaticObjectField(vm, dvmClass, signature);
    }

    @Override
    public DvmObject<?> getObjectField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        if ("android/content/pm/PackageInfo->versionName:Ljava/lang/String;".equals(signature)){
            return new StringObject(vm, "2.95.1");
        }
        if ("android/content/pm/PackageInfo->signatures:[Landroid/content/pm/Signature;".equals(signature)){
            Object value = dvmObject.getValue();
            System.out.println("value :"+value);
            return new ArrayObject(vm.resolveClass("android/content/pm/PackageManager"));
        }
        return super.getObjectField(vm, dvmObject, signature);
    }


    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        if ("com/aliyun/TigerTally/s/A->ct()Landroid/content/Context;".equals(signature)){
            return vm.resolveClass("android/app/Application", vm.resolveClass("android/content/ContextWrapper", vm.resolveClass("android/content/Context"))).newObject(signature);
        }
        switch (signature){
            case "com/aliyun/TigerTally/A->pb(Ljava/lang/String;[B)Ljava/lang/String;":
                return new StringObject(vm,"");
        }
        return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }
    @Override
    public DvmObject<?> newObjectV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature){
            case "com/aliyun/TigerTally/s/A$AA-><init>()V":
                return vm.resolveClass("com/aliyun/TigerTally/s/A$AA").newObject(signature);
            case "com/aliyun/TigerTally/s/A$BB-><init>()V":
                return vm.resolveClass("com/aliyun/TigerTally/s/A$BB").newObject(signature);

        }
        return super.newObjectV(vm,dvmClass,signature,vaList);
    }
    @Override
    public FileResult<AndroidFileIO> resolve(Emulator<AndroidFileIO> emulator, String pathname, int oflags) {
        return null;
    }
}