#pragma once

#include <iostream>
#include <functional>

#include "serialize/serialize.h"
#include "async/thread/async_thread_base.h"

namespace dog_torch::crypto::mac
{
	using BinaryData = dog_torch::serialize::BinaryData;
	using PauseableChannel = dog_torch::async::thread::PauseableChannel;

	class CPP_API MacGenerator
	{
	protected:
		BinaryData key_;
	public:
		MacGenerator(const BinaryData& key);
		virtual ~MacGenerator();
		virtual std::string fmt() const;

		virtual BinaryData key() const;
		virtual void set_key(const BinaryData& new_key);
		
		virtual BinaryData generate(const BinaryData& data);
		virtual BinaryData generate(std::istream& input, uint64_t total);
		virtual BinaryData generate(PauseableChannel& pc, std::istream& input, uint64_t total);
		virtual std::string fmt_string() const;
	};
}