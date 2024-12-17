#!/bin/Rscript

args <- commandArgs(trailingOnly = TRUE)
if (length(args) != 2) {
	stop("Error: Not enough arguments")
}

input <- args[1]
output_prefix <- args[2]

library("tidyverse")
data <- read_delim(input, col_types = "nnnnnnnn", delim=";")
data$state = as.factor(data$state)
data <- data %>% mutate(page_fault_queue = page_fault_inserted - page_fault_finished, sweep_queue = sweep_inserted - sweep_finished)
page_fault_group = data %>%
  select(state, time_ns, pending = page_fault_pending, inserted = page_fault_inserted, finished = page_fault_finished, queue = page_fault_queue) %>%
  mutate(type = "page_fault")
sweep_group = data %>%
  select(state, time_ns, pending = sweep_pending, inserted = sweep_inserted, finished = sweep_finished, queue = sweep_queue) %>%
  mutate(type = "sweep")
transformed = bind_rows(page_fault_group, sweep_group) %>% arrange(time_ns)

change_points <- data %>%
  filter(state != lag(state, default = first(state)))

box_plot <- ggplot(transformed, aes(x=state, y=queue, colour=type)) + geom_boxplot()
queue_plot <- ggplot(transformed, aes(x=time_ns, y=queue, colour=type)) + geom_line() +
  geom_vline(xintercept=change_points$time_ns, linetype="dashed", color="green", linewidth=1)
finished_plot <- ggplot(transformed, aes(x=time_ns, y=finished, colour=type)) + geom_line() +
  geom_vline(xintercept=change_points$time_ns, linetype="dashed", color="green", linewidth=1)
ggsave(paste0(output_prefix, "_box.svg"), plot=box_plot)
ggsave(paste0(output_prefix, "_queue.svg"), plot=queue_plot)
ggsave(paste0(output_prefix, "_finished.svg"), plot=finished_plot)
