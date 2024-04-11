#pragma once
#include <Windows.h>
#include <utility>

class AutoHandle {
private:
    HANDLE handle;

public:
    AutoHandle();

    AutoHandle(HANDLE handle);

    ~AutoHandle();

    AutoHandle(const AutoHandle&) = delete;
    AutoHandle& operator=(const AutoHandle&) = delete;

    AutoHandle(AutoHandle&& other) noexcept;

    AutoHandle& operator=(AutoHandle&& other) noexcept;

    operator HANDLE();

    void Close();

    operator HANDLE() const {
        return handle;
    }
};