/**
 * MongoConfig.h
 * Simple configuration struct for MongoDB connection parameters.
 * Header-only — no .cpp file needed.
 *
 * C++ Packet Filtering Firewall — DSA Major Project
 * Author: Haris | COMSATS University Islamabad
 */
#pragma once
#include <string>

struct MongoConfig {
    std::string mongoURI  = "mongodb://localhost:27017";   // Connection string
    std::string dbName    = "firewall_db";                 // Database name
    bool dualWriteMode    = true;                          // Write to both MongoDB AND flat-file
};
