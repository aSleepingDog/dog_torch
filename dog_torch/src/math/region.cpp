#include "math/region.h"

namespace NSROOT = dog_torch::math::region;

using dog_torch::utils::from_c_str;

using dog_torch::utils::from_uint64;
using dog_torch::utils::array_to_view;


constexpr auto ERROR_UNEXPECT_CHAR = from_c_str("Unexpected character");
constexpr auto ERROR_UNEXPECT_FORMAT = from_c_str("Unexpected format");
constexpr auto ERROR_NUMBER_OVERFLOW = from_c_str("Number is too big");

uint64_t NSROOT::identify_integer(std::string_view::const_iterator& pos, const std::string_view::const_iterator& end)
{
    /*
                   +-[0-9]-+
                   v       |
         +-[1-9]-->D-------+------------------------+
         |                                     +c8+ |
         |                                     v  | v
         |          +-([1-7]|O|o)-->O---+-c8->O1--+>E0
         |          |                   |      +c2+ |
         |          |                   |      v  | |
    -->S-+--[0]--->R+----(B|b)----->B-+-)-c2->B1--+-+
         |          |                 +-+      +cH+ |
         |          |                   |      v  | |
         |          +----(H|h)----->H-+-)-cH->H1--+-+
         |          |                 +-+           |
         |          |                   |           |
         v          +-------------------)-----------+
         EC<----------------------------+
       c8=[0-7]
       c2=[0-1]
       cH=([0-9]|[a-f]|[A-F])
     */
    uint64_t number = 0;
    /*
    * 0-begin S
    * 1-radix R
    * 2-10    D
    * 3-16    H
    * 4-16 e  H1
    * 5-8     O
    * 6-8 e   O1
    * 7-2     B
    * 8-2 e   B1
    * 127-end   E
    * -1 - u char
    * -2 - overflow
    */
    int8_t stage = 0;
    while (pos != end)
    {
        char c = *pos;
        if (stage == 0)
        {
            if (c >= '1' && c <= '9')
            {
                stage = 2;
                number += (c - '0');
            }
            else if (c == '0')
            {
                stage = 1;
            }
            else
            {
                stage = -1;
            }
        }
        else if (stage == 1)
        {
            if (c >= '0' && c <= '7')
            {
                number = c - '0';
                stage = 5;
            }
            else if (c == 'O' || c == 'o')
            {
                stage = 5;
            }
            else if (c == 'B' || c == 'b')
            {
                stage = 7;
            }
            else if (c == 'X' || c == 'x')
            {
                stage = 3;
            }
            else
            {
                stage = 127;break;
            }
        }
        else if (stage == 2)
        {
            if (c >= '0' && c <= '9')
            {
                if (number > UINT64_MAX / 10)
                {
                    stage = -2;
                    break;
                }
                number *= 10;
                number += (c - '0');
            }
            else
            {
                stage = 127;break;
            }
        }
        else if (stage == 3)
        {
            if (c >= '0' && c <= '9')
            {
                number = c - '0';
                stage = 4;
            }
            else if (c >= 'A' && c <= 'F')
            {
                number = c - 'A' + 10;
                stage = 4;
            }
            else if (c >= 'a' && c <= 'f')
            {
                number = c - 'a' + 10;
                stage = 4;
            }
            else
            {
                stage = -1;
            }
        }
        else if (stage == 4)
        {
            // Validate the digit BEFORE shifting, so a trailing delimiter
            // ends the number without corrupting it (and without a spurious
            // overflow check on an already-complete value).
            uint8_t digit;
            if (c >= '0' && c <= '9') { digit = c - '0'; }
            else if (c >= 'A' && c <= 'F') { digit = c - 'A' + 10; }
            else if (c >= 'a' && c <= 'f') { digit = c - 'a' + 10; }
            else { stage = 127;break; }

            if (number > UINT64_MAX / 16)
            {
                stage = -2;
                break;
            }
            number <<= 4;
            number |= digit;
        }
        else if (stage == 5)
        {
            if (c >= '0' && c <= '7')
            {
                number = c - '0';
            }
            else
            {
                stage = -1;
            }
            stage = 6;
        }
        else if (stage == 6)
        {
            if (c < '0' || c > '7') { stage = 127;break; }
            if (number > UINT64_MAX / 8)
            {
                stage = -2;
                break;
            }
            number <<= 3;
            number += (c - '0');
        }
        else if (stage == 7)
        {
            if (c == '0' || c == '1')
            {
                number = c - '0';
            }
            else
            {
                stage = -1;
            }
            stage = 8;
        }
        else if (stage == 8)
        {
            if (c != '0' && c != '1') { stage = 127;break; }
            if (number > UINT64_MAX / 2)
            {
                stage = -2;
                break;
            }
            number <<= 1;
            number += (c - '0');
        }
        else if (stage == 127 || stage < 0)
        {
            break;
        }
        ++pos;
    }
    if (stage == -1)
    {
        throw DOG_EXCEPTION(array_to_view(ERROR_UNEXPECT_CHAR));
    }
    else if (stage == -2)
    {
        throw DOG_EXCEPTION(array_to_view(ERROR_NUMBER_OVERFLOW));
    }
    return number;
}

NSROOT::NumberIterator::NumberIterator(std::string_view str)
{
    auto pos = str.begin();
    auto end = str.end();
    /*
    * 0-begin  S
    * 1-list   L
    * 2-gap    g
    * 127-end    E
    * -1 u char
    * -2 u fmt
    */
    int8_t stage = 0;
    char c = *pos;
    if (c >= '0' && c <= '9')
    {
        this->is_list_ = true;
        stage = 1;
    }
    else if (c == '[')
    {
        this->is_list_ = false;
        stage = 2;
    }
    else
    {
        stage = -1;
    }
    if (stage == 1)
    {
        do
        {
            this->numbers_.push_back(identify_integer(pos, end));
            if (pos == end)
            {
                stage = 127;break;
            }
            else
            {
                c = *pos++;
                if (c != ',' && c != '|')
                {
                    throw DOG_EXCEPTION(array_to_view(ERROR_UNEXPECT_CHAR));
                }
            }
        } while (stage == 1);
    }
    else if (stage == 2)
    {
        ++pos;

        this->numbers_.push_back(identify_integer(pos, end));
        if (pos == end)
        {
            throw DOG_EXCEPTION(array_to_view(ERROR_UNEXPECT_FORMAT));
        }
        else if (*pos != ',')
        {
            throw DOG_EXCEPTION(array_to_view(ERROR_UNEXPECT_CHAR));
        }
        ++pos;

        this->numbers_.push_back(identify_integer(pos, end));
        if (pos == end)
        {
            throw DOG_EXCEPTION(array_to_view(ERROR_UNEXPECT_FORMAT));
        }
        else if (*pos != '|')
        {
            throw DOG_EXCEPTION(array_to_view(ERROR_UNEXPECT_CHAR));
        }
        ++pos;

        this->numbers_.push_back(identify_integer(pos, end));
        if (*pos != ']')
        {
            throw DOG_EXCEPTION(array_to_view(ERROR_UNEXPECT_FORMAT));
        }
        ++pos;
        if (pos != end)
        {
            throw DOG_EXCEPTION(array_to_view(ERROR_UNEXPECT_FORMAT));
        }

        if (this->numbers_[1] < this->numbers_[0])
        {
            throw DOG_EXCEPTION(array_to_view(ERROR_UNEXPECT_FORMAT));
        }
        else if (this->numbers_[1] == this->numbers_[0] && this->numbers_[2] != 0)
        {
            throw DOG_EXCEPTION(array_to_view(ERROR_UNEXPECT_FORMAT));
        }
        this->index_ = this->numbers_[0];
    }
}

NSROOT::NumberIterator::NumberIterator(const NumberIterator& other)
{
    this->is_list_ = other.is_list_;
    this->numbers_ = other.numbers_;
    this->index_ = other.index_;
}
NSROOT::NumberIterator& NSROOT::NumberIterator::operator=(const NumberIterator & other)
{
    this->is_list_ = other.is_list_;
    this->numbers_ = other.numbers_;
    this->index_ = other.index_;
    return *this;
}
NSROOT::NumberIterator::NumberIterator(NumberIterator&& other) noexcept
{
    this->is_list_ = other.is_list_;
    this->numbers_ = std::move(other.numbers_);
    this->index_ = other.index_;
}
NSROOT::NumberIterator& NSROOT::NumberIterator::operator=(NumberIterator && other) noexcept
{
    if (this == &other) return *this;
    this->is_list_ = other.is_list_;
    this->numbers_ = std::move(other.numbers_);
    this->index_ = other.index_;
    return *this;
}

bool NSROOT::NumberIterator::have_next() const
{
    if (this->is_list_)
    {
        return this->numbers_.size() > this->index_;
    }
    else
    {
        return this->index_ <= this->numbers_[1];
    }
}

uint64_t NSROOT::NumberIterator::next()
{
    if (this->is_list_)
    {
        return this->numbers_[this->index_++];
    }
    else
    {
        uint64_t temp = this->index_;
        this->index_ += this->numbers_[2];
        return temp;
    }
}

#define NAMESPACE(name) dog_torch__region__##name
#define UTILS(name) dog_torch__utils__##name

NAMESPACE(NumberIterator)* NAMESPACE(NumberIterator_create)(LVALUE(UTILS(CppResultSet))result_set, LVALUE(UTILS(CppString))string)
{
    using dog_torch::utils::to_string;
    using dog_torch::utils::CppResultSet_reset;
    try
    {
        return new NAMESPACE(NumberIterator)(to_string(string));
    }
    catch (const std::exception& e)
    {
        CppResultSet_reset(result_set, -1, e.what());
        return nullptr;
    }
}

UTILS(CppUint64Array)* NAMESPACE(NumberIterator_all_numbers)(LVALUE(NAMESPACE(NumberIterator))self)
{
    std::vector<uint64_t> r;
    while (self->have_next())
    {
        r.push_back(self->next());
    }
    return dog_torch::utils::to_c_style(r);
}

void NAMESPACE(NumberIterator_delete)(NAMESPACE(NumberIterator)** self)
{
    DEFAULT_DESTOTY(self);
}

uint8_t NAMESPACE(NumberIterator_have_next)(const LVALUE(NAMESPACE(NumberIterator))self)
{
    if (self == nullptr) return 0;
    return self->have_next() ? 1 : 0;
}

uint64_t NAMESPACE(NumberIterator_next)(LVALUE(NAMESPACE(NumberIterator))self)
{
    if (self == nullptr) return 0;
    return self->next();
}
#undef NAMESPACE
#undef UTILS