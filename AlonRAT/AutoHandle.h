#pragma once
#include <Windows.h>

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

    void Close();

    operator HANDLE() const {
        return handle;
    }
};