#!/usr/bin/python
from threading import Thread
from Queue import Queue

class Worker(Thread):
    def __init__(self, task_queue):
        Thread.__init__(self)
        self.task_queue = task_queue
        self.Deamon = True
        self.start()

    def run(self):
        while True:
            func, args = self.task_queue.get()
            try:
                func(*args)
            except Exception as e:
                print(e)
            finally:
                self.task_queue.task_done()


class ThreadPool:
    def __init__(self, num_threads):
        self.task_queue = Queue(num_threads)
        for _ in range(num_threads):
            Worker(self.task_queue)

    def add_task(self, func, *args):
        self.task_queue.put((func, args))

    def map(self, func, arg_list):
        for arg in arg_list:
            self.add_task(func, arg)

    def wait_completion(self):
        self.task_queue.join()


if __name__ == '__main__':
    from random import randrange
    from time import sleep

    def wait_delay(sec):
        print("Delay %d seconds\n" % sec)
        sleep(sec)

    delays = [randrange(1, 3) for i in range(1, 20)]

    pool = ThreadPool(5)

    pool.map(wait_delay, delays)
    pool.wait_completion()
    print("Task Queue Completed.\n")
