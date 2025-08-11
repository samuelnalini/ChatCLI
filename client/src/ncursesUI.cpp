#include "headers/ncursesUI.hpp"
#include "utf8.h"
#include "debug.hpp"

#include <ncurses.h>
#include <locale.h>
#include <optional>
#include <wchar.h>

NcursesUI::NcursesUI()
    : m_msgWin(nullptr)
    , m_inputWin(nullptr)
{}

NcursesUI::~NcursesUI() {}

inline void NcursesUI::DrawWindows()
{
    if (m_msgWin)
    {
        delwin(m_msgWin);
    }

    if (m_inputWin)
    {
        delwin(m_inputWin);
    }

    getmaxyx(stdscr, m_rows, m_cols);

    m_msgWin = newwin(m_rows - INPUT_HEIGHT, m_cols, 0, 0) ;
    m_inputWin = newwin(INPUT_HEIGHT, m_cols, m_rows - INPUT_HEIGHT, 0);

    scrollok(m_msgWin, TRUE);
    box(m_inputWin, 0, 0);

    keypad(m_inputWin, TRUE);
    nodelay(m_inputWin, TRUE);
    wtimeout(m_inputWin, 0);

    wrefresh(m_msgWin);
    wrefresh(m_inputWin);
}

inline void NcursesUI::WindowResize()
{
    if (m_inputWin)
    {
        delwin(m_inputWin);
    }

    getmaxyx(stdscr, m_rows, m_cols);
    redrawwin(m_msgWin);   

    m_inputWin = newwin(INPUT_HEIGHT, m_cols, m_rows - INPUT_HEIGHT, 0);
    box(m_inputWin, 0, 0);
    keypad(m_inputWin, TRUE);
    nodelay(m_inputWin, TRUE);
    wtimeout(m_inputWin, 0);   

    wrefresh(m_msgWin);
    wrefresh(m_inputWin);
}

void NcursesUI::Init()
{
    setlocale(LC_ALL, "");
    start_color();
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(1);

    DrawWindows();

    running = true;

    Debug::Log("UI Initialized");
}

void NcursesUI::Cleanup()
{
    running = false;
    Debug::Log("Started UI cleanup procedure");

    if (m_msgWin)
    {
        delwin(m_msgWin);
        Debug::Log("==> Deleted msg win");
    }

    if (m_inputWin)
    {
        delwin(m_inputWin);
        Debug::Log("==> Deleted input win");
    }

    endwin();
    Debug::Log("==> Called endwin()");
}

bool NcursesUI::GetInputChar(wint_t& ch)
{
    if (!running)
        return false;

    std::lock_guard<std::mutex> lock(m_mutex);

    int result{ wget_wch(m_inputWin, &ch) };

    return result != ERR;
}

std::string to_utf8(const std::wstring& wstr)
{
    std::string result;
    utf8::utf32to8(wstr.begin(), wstr.end(), std::back_inserter(result));
    return result;
}

std::wstring from_utf8(const std::string& str)
{
    std::wstring out;
    utf8::utf8to32(str.begin(), str.end(), std::back_inserter(out));
    return out;
}

void NcursesUI::PushMessage(const std::string& msg)
{
    if (!running)
    {
        Debug::Log("Attempted to push message without UI -> dropping", Debug::LOG_LEVEL::WARNING);
        return;
    }

    std::lock_guard<std::mutex> lock(m_queueMutex);
    m_msgQueue.push(msg);
}

void NcursesUI::PushPriorityMessage(const std::string& msg)
{
    if (!running)
    {
        Debug::Log("Attempted to push message without UI -> dropping", Debug::LOG_LEVEL::WARNING);
        return;
    }

    std::wstring wmsg{ from_utf8(msg) };
    wmsg.push_back(L'\n');

    mvwaddwstr(m_msgWin, getcury(m_msgWin), 0, wmsg.c_str());

    wrefresh(m_msgWin);
    wrefresh(m_inputWin);
}

void NcursesUI::PrintBufferedMessages()
{
    if (!running)
        return;
    
    std::unique_lock<std::mutex> lock(m_mutex, std::defer_lock);
    std::unique_lock<std::mutex> lock2(m_queueMutex, std::defer_lock);
    std::lock(lock, lock2);
    
    bool printed{ false };
    while (!m_msgQueue.empty())
    {
        std::string msg{ m_msgQueue.front() };
        m_msgQueue.pop();

        std::wstring wmsg{ from_utf8(msg) };
        wmsg.push_back(L'\n');

        mvwaddwstr(m_msgWin, getcury(m_msgWin), 0, wmsg.c_str());
        printed = true;
        Debug::Log("Printed message " + msg);
    }

    if (printed)
    {
        wrefresh(m_msgWin);
        wrefresh(m_inputWin);
    }
}


void NcursesUI::RedrawInputLine(const std::string& prompt, const std::wstring& inputBuffer, size_t cursorPos)
{
    if (!running)
        return;

    std::lock_guard<std::mutex> lock(m_mutex);

    werase(m_inputWin);
    box(m_inputWin, 0, 0);

    mvwprintw(m_inputWin, 1, 1, "%s", prompt.c_str());

    int startX{ 1 + static_cast<int>(prompt.length()) };
    mvwaddwstr(m_inputWin, 1, startX, inputBuffer.c_str());

    int visualCursorOffset{ 0 };

    for (size_t i{ 0 }; i < cursorPos && i < inputBuffer.size(); ++i)
    {
        int w{ wcwidth(inputBuffer[i]) };
        if (w > 0)
            visualCursorOffset += w;
    }

    wmove(m_inputWin, 1, startX + visualCursorOffset);
    wrefresh(m_inputWin);
}

std::optional<std::string> NcursesUI::PromptInput(const std::string& prompt)
{
    if (!running)
        return std::nullopt;

    std::wstring input;
    size_t cursorPos{ 0 };

    RedrawInputLine(prompt, input, cursorPos);

    wint_t ch{};
    while (running)
    {
        int result{ wget_wch(m_inputWin, &ch) };
        
        if (result == ERR)
            continue;

        if (ch == L'\n')
            break;


        switch(ch)
        {
            case KEY_BACKSPACE:
            case 127:
            case '\b':
                if (cursorPos > 0)
                {
                    input.erase(cursorPos - 1, 1);
                    --cursorPos;
                }
                break;
            case KEY_LEFT:
                if (cursorPos > 0)
                    --cursorPos;
                break;
            case KEY_RIGHT:
                if (cursorPos < input.size())
                    ++cursorPos;
                break;
            case KEY_UP:
            case KEY_DOWN:
                break;
            case KEY_DC:
                if (cursorPos < input.size())
                    input.erase(cursorPos, 1);
                break;
            case KEY_HOME:
                cursorPos = 0;
                break;
            case KEY_END:
                cursorPos = input.size();
                break;
            case KEY_RESIZE:
                WindowResize();
                break;
            default:
                if (iswprint(ch))
                {
                    input.insert(cursorPos, 1, ch);
                    ++cursorPos;
                }
                break;
        }
        RedrawInputLine(prompt, input, cursorPos);
    }

    return to_utf8(input);
}
