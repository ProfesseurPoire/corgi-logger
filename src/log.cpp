#include <corgi/logger/log.h>

#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#ifdef _WIN32
// Only here so I can have colors on windows
#    include <windows.h>
// Yoloed that, probably won't work on linux
// Helps with the stack trace
#    include <DbgHelp.h>
#    pragma comment(lib, "dbghelp.lib")
#endif

static void set_console_color(unsigned short color)
{
#ifdef _WIN32
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
#endif
}

using namespace corgi;
using namespace std;

struct Channel
{
    // Stores the logs for each log level
    std::map<logger::LogLevel, std::vector<std::string>> logs {
        {logger::LogLevel::Info, std::vector<std::string>()},
        {logger::LogLevel::Trace, std::vector<std::string>()},
        {logger::LogLevel::Debug, std::vector<std::string>()},
        {logger::LogLevel::Warning, std::vector<std::string>()},
        {logger::LogLevel::Error, std::vector<std::string>()},
        {logger::LogLevel::FatalError, std::vector<std::string>()}};
};

static const std::map<corgi::logger::LogLevel, unsigned short> color_code {
    {logger::LogLevel::Info, (unsigned short)11},
    {logger::LogLevel::Trace, (unsigned short)10},
    {logger::LogLevel::Debug, (unsigned short)13},
    {logger::LogLevel::Warning, (unsigned short)14},
    {logger::LogLevel::Error, (unsigned short)12},
    {logger::LogLevel::FatalError, (unsigned short)12}};

static std::map<std::string, Channel> channels_;
static bool                           show_time_ {true};
static bool                           write_logs_in_console_ {true};
static bool                           write_logs_in_file_ {true};

static std::string                          output_folder_ {"logs"};
static std::map<std::string, std::ofstream> files_;

// Set that to false if you don't want the log operations to write
// inside a file

namespace
{
auto get_time() -> std::string
{
    auto  time   = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    auto* gmtime = std::gmtime(&time);

    std::string minutes = std::to_string(gmtime->tm_min);
    if(gmtime->tm_min < 10)
        minutes = "0" + minutes;

    std::string seconds = std::to_string(gmtime->tm_sec);
    if(gmtime->tm_sec < 10)
        seconds = "0" + seconds;

    return (std::to_string(gmtime->tm_hour) + ":" + minutes + ":" + seconds);
}

auto filename(const std::string& path) -> std::string
{
    for(size_t i = path.size() - 1; i > 0; --i)
    {
        if(path[i] == '/' || path[i] == '\\')
        {
            return path.substr(
                i + 1, std::string::npos);    //npos means until the end of the string
        }
    }
    return "";
}

auto build_string(corgi::logger::LogLevel log_level,
                  int                     line,
                  const std::string&      file,
                  const std::string&      func,
                  const std::string&      text,
                  const std::string&      channel) -> std::string
{
    return "[" + channel + "]" + " [" + log_level_str.at(log_level) + "] [" +
           filename(file) + "::" + func + ":" + std::to_string(line) + "] : " + text +
           "\n";
}
}    // namespace

void logger::toggle_file_output(const bool value)
{
    write_logs_in_file_ = value;
}

void logger::toggle_console_output(const bool value)
{
    write_logs_in_console_ = value;
}

void logger::show_time(const bool v)
{
    show_time_ = v;
}

void logger::set_folder(const std::string& path)
{
    output_folder_ = path;
}

void logger::close_files()
{
    for(auto& file : files_)
        file.second.close();
}

void logger::details::write_log(const std::string& obj,
                                const LogLevel     log_level,
                                const std::string& channel,
                                const std::string& file,
                                const std::string& func,
                                const int          line)
{
    auto str = build_string(log_level, line, file, func, obj, channel);

    set_console_color(color_code.at(log_level));

    if(show_time_)
        str = "[" + get_time() + "] " + str;

    if(write_logs_in_console_)
        std::cout << str << std::flush;

    channels_[channel].logs.at(log_level).push_back(str);

    if(write_logs_in_file_)
    {
        if(!files_[channel].is_open())
        {
            //Creates the directory to store the logs if it doesn't exist already
            std::filesystem::create_directory(output_folder_);

            // Opening/closing to erase the content of the file, a bit weird
            // but if I open the file with trunc it won't write on it
            files_[channel].open((output_folder_ + "/" + channel + ".log"),
                                 std::ofstream::out | std::ofstream::trunc);
            files_[channel].close();
            files_[channel].open((output_folder_ + "/" + channel + ".log"),
                                 std::ofstream::out | std::ofstream::app);
        }
        if(files_[channel].is_open())
        {
            files_[channel] << str;
        }
    }

    if(log_level == logger::LogLevel::FatalError || log_level == logger::LogLevel::Error)
    {
#ifdef _WIN32

        // Actually show the stack

        void*  stack[200];
        HANDLE process = GetCurrentProcess();
        SymInitialize(process, NULL, TRUE);
        WORD         numberOfFrames = CaptureStackBackTrace(0, 200, stack, NULL);
        SYMBOL_INFO* symbol =
            (SYMBOL_INFO*)malloc(sizeof(SYMBOL_INFO) + (200 - 1) * sizeof(TCHAR));
        symbol->MaxNameLen   = 200;
        symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        DWORD            displacement;
        IMAGEHLP_LINE64* l = (IMAGEHLP_LINE64*)malloc(sizeof(IMAGEHLP_LINE64));
        l->SizeOfStruct    = sizeof(IMAGEHLP_LINE64);
        for(int i = 0; i < numberOfFrames; i++)
        {
            DWORD64 address = (DWORD64)(stack[i]);
            SymFromAddr(process, address, NULL, symbol);
            if(SymGetLineFromAddr64(process, address, &displacement, l))
            {
                printf("\tat %s in %s: line: %lu: address: 0x%0X\n", symbol->Name,
                       l->FileName, l->LineNumber,
                       static_cast<unsigned int>(symbol->Address));
            }
            else
            {
                /*printf("\tSymGetLineFromAddr64 returned error code %lu.\n", GetLastError());
                printf("\tat %s, address 0x%0X.\n", symbol->Name, symbol->Address);*/
            }
        }
#endif
    }
}