#pragma once
#include <gsl/multi_span>
#include <droidCrypto/Defines.h>
#include <droidCrypto/MatrixView.h>
#include <cstring>

namespace droidCrypto
{
    enum class AllocType
    {
        Uninitialized,
        Zeroed
    };

    template<typename T>
    class Matrix : public MatrixView<T>
    {
        uint64_t mCapacity = 0;
    public:
        Matrix()
        {}

        Matrix(uint64_t rows, uint64_t columns, AllocType t = AllocType::Zeroed)
        {
            resize(rows, columns, t);
        }



        Matrix(const MatrixView<T>& copy)
            : MatrixView<T>(new T[copy.size()], copy.bounds()[0], copy.stride())
            , mCapacity(copy.size())
        {
            memcpy(MatrixView<T>::mView.data(), copy.data(), copy.mView.size_bytes());
        }

        Matrix(Matrix<T>&& copy)
            : MatrixView<T>(copy.data(), copy.bounds()[0], copy.stride())
            , mCapacity(copy.mCapacity)
        {
            copy.mView = span<T>();
            copy.mStride = 0;
            copy.mCapacity = 0;
        }


        ~Matrix()
        {
            delete[] MatrixView<T>::mView.data();
        }


        const Matrix<T>& operator=(const Matrix<T>& copy)
        {
            resize(copy.rows(), copy.stride());
            memcpy(MatrixView<T>::mView.data(), copy.data(), copy.mView.size_bytes());
            return copy;
        }


        void resize(uint64_t rows, uint64_t columns, AllocType type = AllocType::Zeroed)
        {
            if (rows * columns > mCapacity)
            {
                mCapacity = rows * columns;
                auto old = MatrixView<T>::mView;

                if (type == AllocType::Zeroed)
                    MatrixView<T>::mView = span<T>(new T[mCapacity](), mCapacity);
                else
                    MatrixView<T>::mView = span<T>(new T[mCapacity], mCapacity);


                auto min = std::min<uint64_t>(old.size(), mCapacity) * sizeof(T);
                memcpy(MatrixView<T>::mView.data(), old.data(), min);

                delete[] old.data();

            }
            else
            {
                auto newSize = rows * columns;
                if (newSize > MatrixView<T>::size() && type == AllocType::Zeroed)
                {
                    memset(MatrixView<T>::data() + MatrixView<T>::size(), 0, newSize - MatrixView<T>::size());
                }

                MatrixView<T>::mView = span<T>(MatrixView<T>::data(), newSize);
            }

            MatrixView<T>::mStride = columns;
        }


        // return the internal memory, stop managing its lifetime, and set the current container to null.
        T* release()
        {
            auto ret = MatrixView<T>::mView.data();
            MatrixView<T>::mView = {};
            mCapacity = 0;
            return ret;
        }
    };


}
