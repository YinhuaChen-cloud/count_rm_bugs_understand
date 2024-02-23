#!/usr/bin/env python3
# coding=utf-8
# python >= 3.5
# From https://github.com/AngoraFuzzer/Angora/blob/master/tools/lava_validation.py
"""
python3 lava_validation.py path-to-output-dir path-to-validated_bugs-file path-to-program [args..]
e.g.
python3 lava_validation.py ./output/ ./path-to-lava-M/who/validated_bugs ./who 
python3 lava_validation.py ./output/ ./path-to-lava-M/md5sum/validated_bugs ./md5sum -c

"""
# 执行这个脚本的命令是:
# python3 $TARGET/count_rm_bugs.py $SHARED/findings/default/ "$TARGET/LAVA-M/$PROGRAM/validated_bugs" $OUT/afl/$PROGRAM $args
# python3  py脚本路径  fuzzing结果存放目录  对应的PUT的bugs序列  PUT路径  PUT参数
# python3 /magma/targets/lavam/count_rm_bugs.py /magma_shared/findings/default/ /magma/targets/lavam/LAVA-M/base64/validated_bugs /magma_out/afl/base64 -d
import sys                                                                             
import os     
import subprocess        
import time                 
import shutil

# 打开 path 指定的文件，往里面添加新的一行 pstr
def append_file(pstr, path):                    
    f = open(path, 'a')                           
    f.write("%s\n" % pstr)
    f.close()
    return               

def sub_run(cmd, timeout):
    try: 
         r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout)
         return r
    except subprocess.TimeoutExpired:
        print("time out")
        return None
    return None
                                     
# crash_dirs = [./output_dir/default/crashes/, ./output_dir/default/queue/]
# prom_bin = PUT路径
# flags = PUT执行参数
# save_dir = ./output_dir/default/bugs/
# bugs_id = {}
def locate_crashes(crash_dirs, prom_bin, flags, save_dir, bugs_id={}):
    for cur_dir in crash_dirs:
        # 如果是 ./output_dir/default/crashes/ 文件夹，则 is_crash_dir = True
        # 如果是 ./output_dir/default/queue/ 文件夹，则 is_crash_dir = False
        is_crash_dir = cur_dir.endswith("crashes/")
        # for loop: 列出 crashes/queue 文件夹下的所有内容 (放进一个列表里)
        for file in os.listdir(cur_dir):
            # 如果不是 README.txt 才会继续执行里面的代码
            if (file != "README.txt"):                
                # cur_file = ./output_dir/default/crashes/seed_filename
                cur_file = cur_dir + file
                # cmd = [PUT路径]

                # 下面这几行的目的是为了构建一个完整的命令
                cmd = [prom_bin]            
                for flag in flags:
                    cmd.append(flag)
                cmd.append(cur_file)
                cmd = ["timeout", "-s", "KILL", "--preserve-status", "4"] + cmd
                # 命令：
                print(cmd)
                # ['timeout', '-s', 'KILL', '--preserve-status', '4', './afl/base64', '-d', './output_dir/default//crashes/id:000000,sig:11,src:000000,time:500,execs:201,op:its,pos:0']
                # 翻译成人话就是下面这行：
                # timeout -s KILL --preserve-status 4 ./afl/base64 -d ./output_dir/default//crashes/id:000000,sig:11,src:000000,time:500,execs:201,op:its,pos:0

                r = sub_run(cmd, 6)
                if r is None:
                    continue
                out = r.stdout.split(b'\n')
                has_crash_id = False      
                for line in out:
                    if line.startswith(b"Successfully triggered bug"):
                        dot = line.split(b',')[0]
                        cur_id = int(dot[27:])
                        has_crash_id = True
                        if cur_id not in bugs_id:                        
                            print("  Trigger %5d in: %s" % (cur_id, cur_file))
                            if is_crash_dir:
                                sub_run(["mv", cur_file, save_dir + "bug-" + str(cur_id)], 3)
                            else:
                                sub_run(["cp", cur_file, save_dir + "bug-" + str(cur_id)], 3)
                            bugs_id[cur_id] = 1
                        else:
                            bugs_id[cur_id] += 1       
                            if is_crash_dir:
                                sub_run(["rm", cur_file], 3)
                if has_crash_id == False and is_crash_dir:
                    print("  NO Trigger       for: %s" % cur_file)
    return bugs_id

# python3 $TARGET/count_rm_bugs.py $SHARED/findings/default/ "$TARGET/LAVA-M/$PROGRAM/validated_bugs" $OUT/afl/$PROGRAM $args
# python3  py脚本路径  fuzzing结果存放目录  对应的PUT的bugs序列  PUT路径  PUT参数
# python3 /magma/targets/lavam/count_rm_bugs.py /magma_shared/findings/default/ /magma/targets/lavam/LAVA-M/base64/validated_bugs /magma_out/afl/base64 -d
if __name__ == "__main__":
    flags = []                                              
    fuzzer = ""                                                               
    prom = ""                                               
    output_dir = ""
    val_file = ""
    if len(sys.argv) > 3:
        # output_dir = fuzzing 结果存放目录
        output_dir = sys.argv[1]
        # val_file = validated_bugs 这个文件的路径
        val_file = sys.argv[2]
        # prom = PUT路径
        prom = sys.argv[3]
    else:
        print("The command format is : dir(e.g. output) validated_file(lava provide) prom(e.g. base64) {flags(-d)}")
        exit()
    if len(sys.argv) > 4:
        # flags = PUT参数
        flags = sys.argv[4:]

    print("Target progrom is : ", prom, flags)
    # Target progrom is :  ./afl/base64 ['-d']

    val_ids = []
    extra_ids = []
    with open(val_file, 'r') as f:
        d = f.read()
        # 到这行，d 已经读取了 validated_bugs 里的所有内容
        val_ids = list(map(int, d.split()))
        sorted(val_ids)

    # val_ids = 
    # [1, 222, 235, 253, 255, 276, 278, 284, 386, 554, 556, 558, 560, 562, 566, 572, 573, 576, 582, 583, 584, 774, 776, 778, 780, 782, 784, 786, 788, 790, 792, 798, 804, 805, 806, 813, 815, 817, 831, 832, 835, 841, 842, 843]

    unique_dir = output_dir + "/bugs/"
    # unique_dir = ./output_dir/default/bugs/

    # 如果不存在 ./output_dir/default/bugs/ 这个文件夹，那么创建它
    if not os.path.isdir(unique_dir):
        os.mkdir(unique_dir)
    crash_dirs = [output_dir + "/crashes/", output_dir + "/queue/"]
    # crash_dirs = [./output_dir/default/crashes/, ./output_dir/default/queue/]
    log_file = output_dir + "/bug_log.txt"
    # log_file = ./output_dir/default/bug_log.txt
    cnt_file = output_dir + "/bug_cnt.txt"
    # cnt_file = ./output_dir/default/bug_cnt.txt
    bugs_id = {}

    t0 = int(time.time())
    # 它用于获取当前的系统时间，返回一个浮点数表示的时间戳，以秒为单位，
    # 从 1970 年 1 月 1 日午夜（UTC）开始计算。

    while True:
        # 计算当前时间
        t = int(time.time()) - t0
        print("Collecting bugs at %d" % t)
        # Collecting bugs at [程序开始后的秒数]
        bugs_id = locate_crashes(crash_dirs, prom, flags, unique_dir, bugs_id)
        # bugs_id = locate_crashes(crash_dirs, prom, flags, unique_dir, bugs_id)
        # crash_dirs = [./output_dir/default/crashes/, ./output_dir/default/queue/]
        # prom = PUT路径
        # flags = PUT执行参数
        # unique_dir = ./output_dir/default/bugs/

        # Collecting bugs at 0
        # bugs_id = {}
        # Collecting bugs at 16
        # {788: 5, 782: 5, 566: 5, 792: 3, 784: 5, 560: 3, 1: 6, 278: 3, 276: 5, 562: 5, 786: 5, 790: 3, 235: 5, 274: 5}
        # Collecting bugs at 33
        # {788: 5, 782: 5, 566: 5, 792: 3, 784: 5, 560: 3, 1: 6, 278: 3, 276: 5, 562: 5, 786: 5, 790: 3, 235: 10, 274: 10}
        # Collecting bugs at 49
        # {788: 5, 782: 5, 566: 5, 792: 3, 784: 5, 560: 3, 1: 6, 278: 3, 276: 5, 562: 5, 786: 5, 790: 3, 235: 15, 274: 15}
        # 下一次打印 Collecting bugs at xx
        # {788: 5, 782: 5, 566: 5, 792: 3, 784: 5, 560: 3, 1: 6, 278: 3, 276: 5, 562: 5, 786: 5, 790: 3, 235: 20, 274: 20}

        id_lists = list(bugs_id.keys())
        id_lists.sort()

        # id_lists = [1, 235, 274, 276, 278, 560, 562, 566, 782, 784, 786, 788, 790, 792, 805]

        # 如果一个在 id_lists 里的 “序号i” 既不在 val_ids 这个列表里，也不在 extra_ids 这个列表里，那么就把它放进 extra_ids 这个列表里
        for i in id_lists:
            if i not in val_ids and i not in extra_ids:
                extra_ids.append(i)

        # log_file = ./output_dir/default/bug_log.txt

        # append_file 这个函数的作用是，往某个文件添加新的一行，那一行的内容就是第一个参数
        append_file("-" * 80, log_file)
        append_file("Found ids: " + " ".join(str(i) for i in id_lists), log_file)
        append_file("Number of found ids: " + str(len(bugs_id)), log_file)
        append_file("Extra ids: " + " ".join(str(i) for i in extra_ids), log_file)
        fail_ids = list(set(val_ids) - set(id_lists))
        append_file("Fail ids: " + " ".join(str(i) for i in fail_ids), log_file)
        cnt = len(id_lists)

        # 这行代码就是往 bug_cnt.txt 添加新的一行
        append_file("%d,%d" % (t, cnt), cnt_file)

        # 以下是 bug_cnt.txt 的一个例子
        # 0,27
        # 16,36
        # 32,43
        # 48,44

        time.sleep(15)
