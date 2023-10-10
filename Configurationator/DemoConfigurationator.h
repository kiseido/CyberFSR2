#pragma once

// DemoConfigurationator.h
#ifndef DemoConfigurationator_h
#define DemoConfigurationator_h

#include "Configurationator.h"

struct DemoConfigurationator : public Configurationator {
    void loadDefaultValues() override;
};

#endif
