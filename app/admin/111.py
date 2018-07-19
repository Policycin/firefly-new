# import multiprocessing
# import time
# from datetime import datetime
#
# def func(msg):
#     #执行程序需要10s
#     for i in range(10):
#         print(msg)
#         time.sleep(1)
#
# if __name__ == "__main__":
#     time1=datetime.today()
#     pool = multiprocessing.Pool(processes=4)
#     for i in range(10):
#         msg = "hello %d" %(i)
#         # func(msg)
#         pool.apply_async(func, (msg, ))
#     pool.close()
#     pool.join()
#     time2=datetime.today()
#     print("Sub-process(es) done.",time2-time1,"秒")
