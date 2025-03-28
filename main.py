#!/usr/bin/env python3
import argparse
import json
import csv
import xml.etree.ElementTree as ET
import logging
import os
import re
import chardet
from faker import Faker


# Initialize Faker for generating fake data
fake = Faker()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(
        description="Anonymizes structured data (JSON, CSV, XML) by replacing sensitive fields with configurable placeholder values."
    )
    parser.add_argument("input_file", help="Path to the input data file.")
    parser.add_argument("output_file", help="Path to the output anonymized file.")
    parser.add_argument(
        "-f",
        "--format",
        choices=["json", "csv", "xml"],
        required=True,
        help="Format of the input data (json, csv, xml).",
    )
    parser.add_argument(
        "-c",
        "--config",
        help="Path to the configuration file (JSON) containing field anonymization rules.",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging."
    )
    return parser.parse_args()


def load_config(config_file):
    """
    Loads the anonymization configuration from a JSON file.
    Args:
        config_file (str): Path to the JSON configuration file.

    Returns:
        dict: A dictionary containing the anonymization rules.  Returns None if file not found or invalid JSON.
    """
    try:
        with open(config_file, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        logging.error(f"Configuration file not found: {config_file}")
        return None
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON format in configuration file: {config_file}")
        return None


def detect_encoding(file_path):
    """
    Detects the encoding of the input file.

    Args:
        file_path (str): Path to the input file.

    Returns:
        str: The detected encoding, or None if detection fails.
    """
    try:
        with open(file_path, 'rb') as f:
            rawdata = f.read()
        result = chardet.detect(rawdata)
        return result['encoding']
    except Exception as e:
        logging.error(f"Error detecting encoding: {e}")
        return None

def anonymize_json(data, config):
    """
    Anonymizes JSON data based on the provided configuration.

    Args:
        data (dict): The JSON data to anonymize.
        config (dict): The anonymization configuration.

    Returns:
        dict: The anonymized JSON data.
    """
    if not isinstance(data, dict) and not isinstance(data, list):
      return data # Return immediately, avoids crash for non-dicts/lists
    
    if isinstance(data, list):
      return [anonymize_json(item, config) for item in data]

    for key, value in data.items():
        if key in config:
            action = config[key].get("action", "replace")
            placeholder = config[key].get("placeholder", "")
            regex = config[key].get("regex")
            
            if regex:
                try:
                    if isinstance(value, str):
                        data[key] = re.sub(regex, placeholder, value)
                    else:
                        logging.warning(f"Field {key} with regex requires a string value, skipping.")

                except re.error as e:
                    logging.error(f"Invalid regex for field {key}: {e}")
                    continue
                    
            elif action == "replace":
                if placeholder == "fake.name":
                    data[key] = fake.name()
                elif placeholder == "fake.email":
                    data[key] = fake.email()
                elif placeholder == "fake.address":
                    data[key] = fake.address()
                elif placeholder == "fake.phone_number":
                    data[key] = fake.phone_number()
                elif placeholder == "fake.date":
                    data[key] = str(fake.date())
                elif placeholder == "null":
                    data[key] = None  # Use None for JSON null
                else:
                    data[key] = placeholder

            elif action == "remove":
                del data[key]
            else:
                logging.warning(f"Unknown action '{action}' for field '{key}'. Skipping.")

        elif isinstance(value, dict):
            data[key] = anonymize_json(value, config)
        elif isinstance(value, list):
            data[key] = [anonymize_json(item, config) for item in value]
    return data


def anonymize_csv(input_file, output_file, config):
    """
    Anonymizes CSV data based on the provided configuration.

    Args:
        input_file (str): Path to the input CSV file.
        output_file (str): Path to the output anonymized CSV file.
        config (dict): The anonymization configuration (mapping column names to anonymization actions).
    """
    encoding = detect_encoding(input_file)
    if not encoding:
        logging.error("Failed to detect file encoding.  Using utf-8 as default.")
        encoding = 'utf-8'

    try:
        with open(input_file, 'r', encoding=encoding) as infile, open(output_file, 'w', newline='', encoding=encoding) as outfile:
            reader = csv.DictReader(infile)
            fieldnames = reader.fieldnames
            writer = csv.DictWriter(outfile, fieldnames=fieldnames)
            writer.writeheader()

            for row in reader:
                anonymized_row = {}
                for field in fieldnames:
                    if field in config:
                        action = config[field].get("action", "replace")
                        placeholder = config[field].get("placeholder", "")
                        regex = config[field].get("regex")
                        value = row.get(field, "")  # Handle missing columns gracefully

                        if regex:
                            try:
                                if isinstance(value, str):
                                  anonymized_row[field] = re.sub(regex, placeholder, value)
                                else:
                                  logging.warning(f"Field {field} with regex requires string value, skipping.")
                                  anonymized_row[field] = value

                            except re.error as e:
                                logging.error(f"Invalid regex for field {field}: {e}")
                                anonymized_row[field] = value
                        elif action == "replace":
                            if placeholder == "fake.name":
                                anonymized_row[field] = fake.name()
                            elif placeholder == "fake.email":
                                anonymized_row[field] = fake.email()
                            elif placeholder == "fake.address":
                                anonymized_row[field] = fake.address()
                            elif placeholder == "fake.phone_number":
                                anonymized_row[field] = fake.phone_number()
                            elif placeholder == "fake.date":
                                anonymized_row[field] = str(fake.date())
                            else:
                                anonymized_row[field] = placeholder
                        elif action == "remove":
                            anonymized_row[field] = ""  # Or another suitable default
                        else:
                            logging.warning(f"Unknown action '{action}' for field '{field}'. Skipping.")
                            anonymized_row[field] = value  # Keep original if action unknown
                    else:
                        anonymized_row[field] = row[field]
                writer.writerow(anonymized_row)

    except FileNotFoundError:
        logging.error(f"Input file not found: {input_file}")
    except Exception as e:
        logging.error(f"Error processing CSV file: {e}")


def anonymize_xml(input_file, output_file, config):
    """
    Anonymizes XML data based on the provided configuration.

    Args:
        input_file (str): Path to the input XML file.
        output_file (str): Path to the output anonymized XML file.
        config (dict): The anonymization configuration (mapping element paths to anonymization actions).
    """
    try:
        tree = ET.parse(input_file)
        root = tree.getroot()

        for element_path, rule in config.items():
            elements = root.findall(element_path)
            for element in elements:
                action = rule.get("action", "replace")
                placeholder = rule.get("placeholder", "")
                regex = rule.get("regex")

                if regex:
                    try:
                        if element.text:
                            element.text = re.sub(regex, placeholder, element.text)
                    except re.error as e:
                        logging.error(f"Invalid regex for element {element_path}: {e}")

                elif action == "replace":
                    if placeholder == "fake.name":
                        element.text = fake.name()
                    elif placeholder == "fake.email":
                        element.text = fake.email()
                    elif placeholder == "fake.address":
                        element.text = fake.address()
                    elif placeholder == "fake.phone_number":
                        element.text = fake.phone_number()
                    elif placeholder == "fake.date":
                        element.text = str(fake.date())
                    else:
                        element.text = placeholder

                elif action == "remove":
                    parent = find_parent(root, element)
                    if parent is not None:  # Check if parent exists
                        parent.remove(element)
                    else:
                        logging.warning(f"Could not find parent of element {element_path}. Skipping removal.")

                else:
                    logging.warning(f"Unknown action '{action}' for element '{element_path}'. Skipping.")


        tree.write(output_file, encoding="utf-8", xml_declaration=True)

    except FileNotFoundError:
        logging.error(f"Input file not found: {input_file}")
    except ET.ParseError as e:
        logging.error(f"Error parsing XML file: {e}")
    except Exception as e:
        logging.error(f"Error processing XML file: {e}")


def find_parent(root, element):
    """Finds the parent of an element in an XML tree."""
    for parent in root.iter():
        for child in parent:
            if child is element:
                return parent
    return None


def main():
    """
    Main function to execute the data anonymization process.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    config = None
    if args.config:
        config = load_config(args.config)
        if config is None:
            exit(1)

    if not os.path.exists(args.input_file):
        logging.error(f"Input file does not exist: {args.input_file}")
        exit(1)


    try:
        if args.format == "json":
            with open(args.input_file, "r") as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError as e:
                    logging.error(f"Error decoding JSON file: {e}")
                    exit(1)
            if config is None:
                logging.error("Configuration file is required for JSON anonymization.")
                exit(1)
            anonymized_data = anonymize_json(data, config)
            with open(args.output_file, "w") as f:
                json.dump(anonymized_data, f, indent=4)
            logging.info(f"JSON data anonymized and saved to {args.output_file}")
        elif args.format == "csv":
            if config is None:
                logging.error("Configuration file is required for CSV anonymization.")
                exit(1)
            anonymize_csv(args.input_file, args.output_file, config)
            logging.info(f"CSV data anonymized and saved to {args.output_file}")
        elif args.format == "xml":
            if config is None:
                logging.error("Configuration file is required for XML anonymization.")
                exit(1)
            anonymize_xml(args.input_file, args.output_file, config)
            logging.info(f"XML data anonymized and saved to {args.output_file}")
        else:
            logging.error(f"Unsupported format: {args.format}")
            exit(1)

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        exit(1)


if __name__ == "__main__":
    main()