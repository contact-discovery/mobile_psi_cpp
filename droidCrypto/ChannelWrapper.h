#pragma once

#include <droidCrypto/Defines.h>

#include <jni.h>
#include <vector>
#include <deque>


namespace droidCrypto {

    class ChannelWrapper {
    public:

        ChannelWrapper() { clearStats(); };

        virtual void sendAsync(std::vector<block>& data) = 0;

        virtual void send(const std::vector<block>& data) = 0;
        virtual void send(const block& data) = 0;
        virtual void send(uint8_t* data, size_t length) = 0;

        virtual void recvAsync(uint8_t* data, size_t length) = 0;

        virtual void recv(uint8_t* data, size_t length) = 0;
        virtual void recv(block& data) = 0;
        virtual void recv(std::vector<block>& data) = 0;

        void clearStats() { bytes_sent = 0; bytes_recv = 0;}
        uint64_t getBytesSent() { return bytes_sent; }
        uint64_t getBytesRecv() { return bytes_recv; }
    protected:
        uint64_t bytes_sent;
        uint64_t bytes_recv;
    };

    class JavaChannelWrapper : public ChannelWrapper {

    private:
            JNIEnv* mEnv;
            jobject mChannel;
            jmethodID mSendID;
            jmethodID mSendAsyncID;
            jmethodID mSendAsyncVoidID;
            jmethodID mRecvID;
            jmethodID mRecvAsyncID;

    public:
        JavaChannelWrapper(JNIEnv* env, jobject channel);

        void sendAsync(std::vector<block>& data) override;

        void send(const std::vector<block>& data) override;
        void send(const block& data) override;
        void send(uint8_t* data, size_t length) override;

        void recvAsync(uint8_t* data, size_t length) override;

        void recv(uint8_t* data, size_t length) override;
        void recv(block& data) override;
        void recv(std::vector<block>& data) override;
    };

    class CSocketChannel : public ChannelWrapper {

    private:
        int csocket;
        int serversocket;

        void send_all(uint8_t* data, size_t length);
        void recv_all(uint8_t* data, size_t length);

    public:
        CSocketChannel(const char* hostname, uint16_t port, bool isServer);
        ~CSocketChannel();

        void sendAsync(std::vector<block>& data) override;

        void send(const std::vector<block>& data) override;
        void send(const block& data) override;
        void send(uint8_t* data, size_t length) override;

        void recvAsync(uint8_t* data, size_t length) override;

        void recv(uint8_t* data, size_t length) override;
        void recv(block& data) override;
        void recv(std::vector<block>& data) override;
    };

    class BufferChannel : public ChannelWrapper {

    private:
        std::deque<uint8_t> buffer;

    public:
        BufferChannel() = default;
        ~BufferChannel() = default;

        void sendAsync(std::vector<block>& data) override;

        void send(const std::vector<block>& data) override;
        void send(const block& data) override;
        void send(uint8_t* data, size_t length) override;

        void recvAsync(uint8_t* data, size_t length) override;

        void recv(uint8_t* data, size_t length) override;
        void recv(block& data) override;
        void recv(std::vector<block>& data) override;

        std::vector<uint8_t> getBuffer();
        void setBuffer(const std::vector<uint8_t>& buf);
    };
}