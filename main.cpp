#include <iostream>

#include "IpQuery_QQWry.hpp"


int main(int argc, char* argv[])
{
    IpQuery_QQWry _ip_query ("qqwry.dat");
    auto [_info0, _info1, _desp] = _ip_query.find_info ("183.131.62.36");
    std::cout << _info0 << " " << _info1 << " " << _desp << std::endl;
}