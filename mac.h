#pragma once

#include "pch.h"

// arp-send-test 내에 있던 내용을 참고 및 삭제
// 개인적으로 추가하고 싶은 것들 추가 (convert_char_to_int, print, compare)

struct Mac {
public:
	static const uint8_t size = 6;
	
	Mac() {};
	
	Mac(const Mac& m){ memcpy(this->mac_, m.mac_, size); }
	
	Mac(const uint8_t* int_mac){ memcpy(this->mac_, int_mac, this->size); }

	// input 예시 : "FF:FF:FF:FF:FF:FF"
	Mac(const string string_mac) { 
		for(uint8_t i = 0; i <= 16; i+=3)
			this->mac_[i/3] = convert_char_to_int(string_mac[i]) * 16 + convert_char_to_int(string_mac[i+1]); 
	}

	uint32_t convert_char_to_int(const char ch);
	
	void print();
	
	bool compare(Mac com);

	// string return_string();

protected:
	uint8_t mac_[size];
};