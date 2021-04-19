#ifndef LOCKED_QUEUE_H
#define LOCKED_QUEUE_H

#include <list>
#include <mutex>

namespace utility
{
    using namespace std;

    template<class T> class locked_queue
    {
        mutex _mtx;
        list<T> _q;

    public:
        T& back()
        {
            lock_guard<mutex> lg(_mtx);
            return _q.back();
        }
        T& front()
        {
            lock_guard<mutex> lg(_mtx);
            return _q.front();
        }
        T pop_back()
        {
            lock_guard<mutex> lg(_mtx);
            T r = _q.back();
            _q.pop_back();
            return r;
        }
        T pop_front()
        {
            lock_guard<mutex> lg(_mtx);
            T r = _q.front();
            _q.pop_front();
            return r;
        }
        void push_back(const T& data)
        {
            lock_guard<mutex> lg(_mtx);
            _q.push_back(data);
        }
        void push_front(const T& data)
        {
            lock_guard<mutex> lg(_mtx);
            _q.push_front(data);
        }
        size_t size()
        {
            lock_guard<mutex> lg(_mtx);
            return _q.size();
        }
        bool empty()
        {
            lock_guard<mutex> lg(_mtx);
            return _q.empty();
        }
    };
}

#endif
