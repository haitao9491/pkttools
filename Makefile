#
# (C) Copyright 2007-2010
# Hu Chunlin <chunlin.hu@gmail.com>
#
# Makefile - To make my life easier.
#

ROOTDIR = $(shell cd ../.. ; pwd ; cd - > /dev/null)
export ROOTDIR

#-------------------------------------------------------------------------------
# Targets
#-------------------------------------------------------------------------------
exe = sdhpkt_analysis 

#-------------------------------------------------------------------------------
# Customized flags
#-------------------------------------------------------------------------------
IPATH=-I. \
      	-I$(ROOTDIR)/lch/include \
	-I$(ROOTDIR)/lch/apframe \
	-I$(ROOTDIR)/lch/aplog \
	-I$(ROOTDIR)/lch/util 

LIBS=\
	-L$(ROOTDIR)/lch/util -llchutil \
	-L$(ROOTDIR)/lch/apframe -lapfrm \
	-L$(ROOTDIR)/lch/aplog -laplog \
	-lpcap 

SLIBS=\
	$(ROOTDIR)/lch/util/liblchutil.a \
	$(ROOTDIR)/lch/apframe/libapfrm.a \
	$(ROOTDIR)/lch/aplog/libaplog.a 

ifeq ($(T),1)
ifeq ($(CROSS_COMPILE),tile-)
LIBS+=\
      -ltmc -lgxio

SLIBS+=\
      -ltmc -lgxio

endif
endif

#-------------------------------------------------------------------------------
# The real stuff to do the tricks.
#-------------------------------------------------------------------------------
ifneq ($(DAP_CONFIG_MK_INCLUDED),1)
-include $(ROOTDIR)/config.mk
endif

include $(ROOTDIR)/files.mk

#-------------------------------------------------------------------------------
# Dependency, customized
#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
# Dependency, automatically generated.
#-------------------------------------------------------------------------------
-include $(libobjs:.o=.o.dep)
-include $(exe:=.o.dep)

