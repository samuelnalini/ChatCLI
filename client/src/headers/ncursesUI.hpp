#pragma once

#include <ncurses.h>
#include <string>
#include <mutex>
#include <queue>
#include <atomic>
#include <optional>

class NcursesUI
{
public:
    NcursesUI();
    ~NcursesUI();

    void Init();
    void Cleanup();

    bool GetInputChar(wint_t& ch);
    void PushMessage(const std::string& msg);
    void PushPriorityMessage(const std::string& msg);
    void PrintBufferedMessages();
    void RedrawInputLine(const std::string& prompt, const std::wstring& inputBuffer, size_t cursorPos);
    inline void DrawWindows();
    inline void RedrawMessageHistory();

    std::optional<std::string> PromptInput(const std::string& prompt);

public:
    std::atomic<bool> running{ false };

private:
    WINDOW* m_msgWin;
    WINDOW* m_inputWin;
    int m_rows, m_cols;
    std::mutex m_mutex;

    std::queue<std::string> m_msgQueue;
    std::deque<std::wstring> m_history;
    std::mutex m_queueMutex;

    static const int INPUT_HEIGHT = 3;
    static const int MAX_HISTORY = 200;
};
