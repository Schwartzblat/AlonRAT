#include "AutoHandle.h"

AutoHandle::AutoHandle() : handle(nullptr) {}

AutoHandle::AutoHandle(HANDLE handle) : handle(handle) {}

AutoHandle::~AutoHandle() {
    Close();
}

AutoHandle::AutoHandle(AutoHandle&& other) noexcept : handle(nullptr) {
    *this = std::move(other);
}

AutoHandle& AutoHandle::operator=(AutoHandle&& other) noexcept {
    if (this != &other) {
        Close();
        handle = other.handle;
        other.handle = nullptr;
    }
    return *this;
}

AutoHandle::operator HANDLE() {
    return handle;
}

void AutoHandle::Close() {
    if (handle != INVALID_HANDLE_VALUE) {
        CloseHandle(handle);
        handle = nullptr;
    }
}