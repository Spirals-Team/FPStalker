import matplotlib.pyplot as plt
from sklearn import metrics
import random
import math
import datetime
import uuid
from Levenshtein import ratio
from fingerprint import Fingerprint
from sklearn.ensemble import RandomForestClassifier
from sklearn.externals import joblib
import numpy as np

import string
from multiprocessing import Pool, Pipe
import time

results = []


def generate_replay_sequence(fp_set, visit_frequency):
    """
        Takes as input a set of fingerprint fp_set,
        a frequency of visit visit_frequency in days

        Returns a list of fingerprints in the order they must be replayed
    """

    # we start by generating the sequence of replay
    # we don't store the last fp of each user since it's not realistic to replay it infinitely
    user_id_to_fps = dict()
    for fingerprint in fp_set:
        if fingerprint.getId() not in user_id_to_fps:
            user_id_to_fps[fingerprint.getId()] = []
        user_id_to_fps[fingerprint.getId()].append(fingerprint)

    user_id_to_sequence = dict()
    for user_id in user_id_to_fps:
        # can be removed later when we don't set a limit on counter
        if len(user_id_to_fps[user_id]) > 1:
            user_id_to_fps[user_id] = user_id_to_fps[user_id][:-1]
            sequence = []
            last_visit = user_id_to_fps[user_id][0].getStartTime()

            counter_suffix = "i"
            assigned_counter = "%d_%s" % (user_id_to_fps[user_id][0].getCounter(), counter_suffix)
            sequence.append((assigned_counter, last_visit))

            for fingerprint in user_id_to_fps[user_id]:
                counter_suffix = 0
                # if it is none and not the last one (last one is removed)
                #  it means the fp changed within the same time interval
                if fingerprint.getEndTime() is not None:
                    while last_visit + datetime.timedelta(days=visit_frequency) < \
                            fingerprint.getEndTime():
                        last_visit = last_visit + datetime.timedelta(days=visit_frequency)
                        assigned_counter = "%d_%d" % (fingerprint.getCounter(), counter_suffix)
                        sequence.append((assigned_counter, last_visit))
                        counter_suffix += 1

            user_id_to_sequence[user_id] = sequence

    # now we generate the whole sequence
    # we start by merging all the subsequences, and then sort it by the date
    replay_sequence = []
    for user_id in user_id_to_sequence:
        replay_sequence += user_id_to_sequence[user_id]
    replay_sequence = sorted(replay_sequence, key=lambda x: x[1])
    return replay_sequence


def split_data(perc_train, fingerprint_dataset):
    """
        Takes as input the percentage of fingerprints for training and
        the fingerprint dataset ordered chronologically.
        Returns the training and the test sequence
    """
    index_split = int(len(fingerprint_dataset) * perc_train)
    # train, test
    return fingerprint_dataset[: index_split], fingerprint_dataset[index_split:]


def generate_new_id():
    """
        Returns a random user id
    """
    return str(uuid.uuid4())


def candidates_have_same_id(candidate_list):
    """
        Returns True if all candidates have the same id
        Else False
    """
    if len(candidate_list) == 0:
        return False
    return not any(not x for x in [y[2] == candidate_list[0][2] for y in candidate_list])


def rule_based(fingerprint_unknown, user_id_to_fps, counter_to_fingerprint):
    """
        Given an unknown fingerprint fingerprint_unknown,
        and a set of known fingerprints fps_available,
        tries to link fingerprint_unknown to a fingerprint in
        fps_available.
        If it can be linked it returns the id of the fingerprint it has been linked with,
        otherwise it returns a new generated user id.
    """

    forbidden_changes = [
        Fingerprint.CANVAS_JS_HASHED,
        Fingerprint.LOCAL_JS,
        Fingerprint.DNT_JS,
        Fingerprint.COOKIES_JS
    ]

    allowed_changes_with_sim = [
        Fingerprint.USER_AGENT_HTTP,
        Fingerprint.VENDOR,
        Fingerprint.RENDERER,
        Fingerprint.PLUGINS_JS,
        Fingerprint.LANGUAGE_HTTP,
        Fingerprint.ACCEPT_HTTP
    ]

    allowed_changes = [
        Fingerprint.RESOLUTION_JS,
        Fingerprint.ENCODING_HTTP,
        Fingerprint.TIMEZONE_JS
    ]
    ip_allowed = False
    candidates = list()
    exact_matching = list()
    prediction = None
    for user_id in user_id_to_fps:
        for counter_str in user_id_to_fps[user_id]:
            counter_known = int(counter_str.split("_")[0])
            fingerprint_known = counter_to_fingerprint[counter_known]

            # check fingerprint full hash for exact matching
            if fingerprint_known.hash == fingerprint_unknown.hash:
                # either we look if there are multiple users that match
                # in that case we create new id
                # or we assign randomly?
                exact_matching.append((counter_str, None, user_id))
            elif len(exact_matching) < 1 and fingerprint_known.constant_hash == \
                    fingerprint_unknown.constant_hash:
                # we make the comparison only if same os/browser/platform
                if fingerprint_known.val_attributes[Fingerprint.GLOBAL_BROWSER_VERSION] > \
                        fingerprint_unknown.val_attributes[Fingerprint.GLOBAL_BROWSER_VERSION]:
                    continue

                if fingerprint_known.hasFlashActivated() and fingerprint_unknown.hasFlashActivated() and \
                        not fingerprint_known.areFontsSubset(fingerprint_unknown):
                    continue

                forbidden_change_found = False
                for attribute in forbidden_changes:
                    if fingerprint_known.val_attributes[attribute] != \
                            fingerprint_unknown.val_attributes[attribute]:
                        forbidden_change_found = True
                        break

                if forbidden_change_found:
                    continue

                nb_changes = 0
                changes = []
                # we allow at most 2 changes, then we check for similarity
                for attribute in allowed_changes_with_sim:
                    if fingerprint_known.val_attributes[attribute] != \
                            fingerprint_unknown.val_attributes[attribute]:
                        changes.append(attribute)
                        nb_changes += 1

                    if nb_changes > 2:
                        break

                if nb_changes > 2:
                    continue

                sim_too_low = False
                for attribute in changes:
                    if ratio(fingerprint_known.val_attributes[attribute],
                             fingerprint_unknown.val_attributes[attribute]) < 0.75:
                        sim_too_low = True
                        break
                if sim_too_low:
                    continue

                nb_allowed_changes = 0
                for attribute in allowed_changes:
                    if fingerprint_known.val_attributes[attribute] != \
                            fingerprint_unknown.val_attributes[attribute]:
                        nb_allowed_changes += 1

                    if nb_allowed_changes > 1:
                        break

                if nb_allowed_changes > 1:
                    continue

                total_nb_changes = nb_allowed_changes + nb_changes
                if total_nb_changes == 0:
                    exact_matching.append((counter_str, None, user_id))
                else:
                    candidates.append((counter_str, total_nb_changes, user_id))

    if len(exact_matching) > 0:
        if len(exact_matching) == 1 or candidates_have_same_id(exact_matching):
            return exact_matching[0][2]
        elif ip_allowed:
            # we don't use IP address, it is just here because of a previous test!
            for elt in exact_matching:
                counter = int(elt[0].split("_")[0])
                fingerprint_known = counter_to_fingerprint[counter_known]

                if fingerprint_known.val_attributes[Fingerprint.ADDRESS_HTTP] == \
                        fingerprint_unknown.val_attributes[Fingerprint.ADDRESS_HTTP]:
                    prediction = elt[2]
                    break
    else:
        if len(candidates) == 1 or candidates_have_same_id(candidates):
            prediction = candidates[0][2]
        elif ip_allowed:
            # we don't use IP address, it is just here because of a previous test!
            for elt in candidates:
                counter = int(elt[0].split("_")[0])
                fingerprint_known = counter_to_fingerprint[counter_known]

                if fingerprint_known.val_attributes[Fingerprint.ADDRESS_HTTP] == \
                        fingerprint_unknown.val_attributes[Fingerprint.ADDRESS_HTTP]:
                    prediction = elt[2]
                    break

    if prediction is None:
        prediction = generate_new_id()

    return prediction


def simple_eckersley(fingerprint_unknown, user_id_to_fps, counter_to_fingerprint):
    """
        Given an unknown fingerprint fingerprint_unknown,
        and a set of known fingerprints fps_available,
        tries to link fingerprint_unknown to a fingerprint in
        fps_available.
        If it can be linked it returns the id of the fingerprint it has been linked with,
        otherwise it returns a new generated user id.
    """
    # order of attributes matter, should place most discriminative first to decrease average
    # number of comparisons
    attributes_to_test = ["fontsFlashHashed", "pluginsJSHashed", "userAgentHttp", "resolutionJS", "acceptHttp",
                          "timezoneJS", "cookiesJS", "localJS"]

    candidates = list()
    exact = False
    for user_id in user_id_to_fps:
        for counter_str in user_id_to_fps[user_id]:
            attributes_different = 0
            modified_attribute = ""
            counter_known = int(counter_str.split("_")[0])
            fingerprint_known = counter_to_fingerprint[counter_known]

            for attribute in attributes_to_test:
                # special case for Flash fonts
                if attribute == Fingerprint.FONTS_FLASH_HASHED:
                    # we consider that flash activation/deactivation is not a difference
                    if fingerprint_known.hasFlashActivated() and \
                            fingerprint_unknown.hasFlashActivated():
                        if fingerprint_known.val_attributes[attribute] != \
                                fingerprint_unknown.val_attributes[attribute]:
                            attributes_different += 1
                            modified_attribute = attribute
                elif fingerprint_unknown.val_attributes[attribute] != \
                        fingerprint_known.val_attributes[attribute]:
                    attributes_different += 1
                    modified_attribute = attribute

                if attributes_different > 1:
                    break

            if attributes_different == 1:
                # (new_counter, modified_attribute, assigned_id)
                candidates.append((counter_str, modified_attribute, user_id))
            elif attributes_different == 0:
                prediction = user_id
                exact = True

    if len(candidates) == 1 or candidates_have_same_id(candidates):
        if candidates[0][1] in ["cookiesJS", "resolutionJS", "timezoneJS", "IEDataJS",
                                "localJS", "dntJS"]:
            prediction = candidates[0][2]
        else:
            counter_to_test = int(candidates[0][0].split("_")[0])
            ratio_sim = ratio(counter_to_fingerprint[counter_to_test].val_attributes[candidates[0][1]],
                              fingerprint_unknown.val_attributes[candidates[0][1]])
            if ratio_sim > 0.85:
                prediction = candidates[0][2]
            else:
                prediction = generate_new_id()
    elif not exact:
        prediction = generate_new_id()

    return prediction


def replay_scenario(fingerprint_dataset, visit_frequency, link_fingerprint, \
                    filename="./results/scenario_replay_result.csv", model=None, lambda_threshold=None):
    """
        Takes as input the fingerprint dataset,
        the frequency of visit in days,
        link_fingerprint, the function used for the linking strategy
        filename, path to the file to save results of the scenario
    """
    nb_max_cmp = 2
    replay_sequence = generate_replay_sequence(fingerprint_dataset, visit_frequency)
    counter_to_fingerprint = dict()
    for fingerprint in fingerprint_dataset:
        counter_to_fingerprint[fingerprint.getCounter()] = fingerprint

    fps_available = []  # set of known fingerprints (new_counter, new_id)
    user_id_to_fps = dict()
    counter_to_time = dict()
    for index, elt in enumerate(replay_sequence):
        if index % 500 == 0:
            print(index)

        counter_to_time[elt[0]] = elt[1]
        counter = int(elt[0].split("_")[0])
        fingerprint_unknown = counter_to_fingerprint[counter]
        if model is None:
            assigned_id = link_fingerprint(fingerprint_unknown, user_id_to_fps, \
                                           counter_to_fingerprint)
        else:
            assigned_id = link_fingerprint(fingerprint_unknown, user_id_to_fps, \
                                           counter_to_fingerprint, model, lambda_threshold)
        fps_available.append((elt[0], assigned_id))

        if assigned_id not in user_id_to_fps:
            user_id_to_fps[assigned_id] = []
        elif len(user_id_to_fps[assigned_id]) == nb_max_cmp:
            user_id_to_fps[assigned_id].pop(0)

        user_id_to_fps[assigned_id].append(elt[0])

        # every 2000 elements we delete elements too old
        if index % 2000 == 0:
            # 40 days in seconds
            time_limit = 30 * 24 * 60 * 60
            ids_to_remove = set()
            current_time = elt[1]
            for user_id in user_id_to_fps:
                counter_str = user_id_to_fps[user_id][-1]
                time_tmp = counter_to_time[counter_str]
                if (current_time - time_tmp).total_seconds() > time_limit:
                    ids_to_remove.add(user_id)

            for user_id in ids_to_remove:
                del user_id_to_fps[user_id]

    with open(filename, "w") as f:
        for elt in fps_available:
            f.write("%s,%s\n" % (elt[0], elt[1]))

    return fps_available


def generateHeader(attributes):
    header = []
    for attribute in attributes:
        if attribute == Fingerprint.ID:
            pass
        elif attribute == Fingerprint.CREATION_TIME:
            header.append(attribute)
        elif attribute == Fingerprint.ENCODING_HTTP:
            header.append(attribute)
        elif attribute == Fingerprint.TIMEZONE_JS:
            header.append(attribute)
        elif attribute == Fingerprint.PLUGINS_JS:
            header.append("simPlugs")
        elif attribute == Fingerprint.RESOLUTION_JS:
            header.append(attribute)
        elif attribute == Fingerprint.CANVAS_JS_HASHED:
            header.append(attribute)
        elif attribute == Fingerprint.FONTS_FLASH:
            header.append("hasFlash")
            header.append("sameFonts")
        else:
            header.append(attribute)

    header.append("nbChange")
    return header


def compute_similarity_fingerprint(fp1, fp2, attributes, train_mode):
    similarity_vector = []
    flash_activated = fp1.hasFlashActivated() and fp2.hasFlashActivated()
    nb_changes = 0
    for attribute in attributes:
        if attribute == Fingerprint.ID:
            val_to_insert = (1 if fp1.belongToSameUser(fp2) else 0)
            similarity_vector.insert(0, val_to_insert)
        elif attribute == Fingerprint.CREATION_TIME:
            diff = fp1.getTimeDifference(fp2)
            similarity_vector.append(diff)
        elif attribute == Fingerprint.ENCODING_HTTP:
            similarity_vector.append(1) if fp1.hasSameEncodingHttp(fp2) else similarity_vector.append(0)
        elif attribute == Fingerprint.TIMEZONE_JS:
            similarity_vector.append(1) if fp1.hasSameTimezone(fp2) else similarity_vector.append(0)
        elif attribute == Fingerprint.PLUGINS_JS:
            sim = ratio(fp1.val_attributes[attribute], fp2.val_attributes[attribute])
            similarity_vector.append(sim)
        elif attribute == Fingerprint.RESOLUTION_JS:
            similarity_vector.append(1) if fp1.hasSameResolution(fp2) else similarity_vector.append(0)
        elif attribute == Fingerprint.CANVAS_JS_HASHED:
            similarity_vector.append(1) if fp1.hasSameCanvasJsHashed(fp2) else similarity_vector.append(0)
        elif attribute == Fingerprint.FONTS_FLASH:
            if flash_activated:
                similarity_vector.append(1)
                similarity_vector.append(1) if fp1.hasSameFonts(fp2) else similarity_vector.append(0)
            else:
                similarity_vector.append(0)
                similarity_vector.append(0)
        else:
            sim = ratio(str(fp1.val_attributes[attribute]), str(fp2.val_attributes[attribute]))
            similarity_vector.append(sim)

        if fp1.val_attributes[attribute] != fp2.val_attributes[attribute]:
            nb_changes += 1
            if nb_changes > 5 and not train_mode:
                return None, None

    similarity_vector.append(nb_changes)

    return np.asarray(similarity_vector[1:]), np.asarray(similarity_vector[0])


def train_ml(fingerprint_dataset, train_data, load=True, \
             model_path="./data/my_ml_model"):
    if load:
        model = joblib.load(model_path)
    else:
        counter_to_fingerprint = dict()
        index_to_user_id = dict()
        user_ids = set()
        index = 0

        not_to_test = set([Fingerprint.PLATFORM_FLASH,
                           Fingerprint.PLATFORM_INCONSISTENCY,
                           Fingerprint.PLATFORM_JS,
                           Fingerprint.PLUGINS_JS_HASHED,
                           Fingerprint.SESSION_JS,
                           Fingerprint.IE_DATA_JS,
                           Fingerprint.ADDRESS_HTTP,
                           Fingerprint.BROWSER_FAMILY,
                           Fingerprint.COOKIES_JS,
                           Fingerprint.DNT_JS,
                           Fingerprint.END_TIME,
                           Fingerprint.FONTS_FLASH_HASHED,
                           Fingerprint.GLOBAL_BROWSER_VERSION,
                           Fingerprint.LANGUAGE_FLASH,
                           Fingerprint.LANGUAGE_INCONSISTENCY,
                           Fingerprint.LOCAL_JS,
                           Fingerprint.MINOR_BROWSER_VERSION,
                           Fingerprint.MAJOR_BROWSER_VERSION,
                           Fingerprint.NB_FONTS,
                           Fingerprint.NB_PLUGINS,
                           Fingerprint.COUNTER,
                           Fingerprint.OS,
                           Fingerprint.ACCEPT_HTTP,
                           Fingerprint.CONNECTION_HTTP,
                           Fingerprint.ENCODING_HTTP,
                           Fingerprint.RESOLUTION_FLASH,
                           Fingerprint.TIMEZONE_JS,
                           Fingerprint.VENDOR,
                           ])

        att_ml = set(fingerprint_dataset[0].val_attributes.keys())
        att_ml = sorted([x for x in att_ml if x not in not_to_test])

        for fingerprint in fingerprint_dataset:
            counter_to_fingerprint[fingerprint.getCounter()] = fingerprint
            if fingerprint.getId() not in user_ids:
                user_ids.add(fingerprint.getId())
                index_to_user_id[index] = fingerprint.getId()
                index += 1

        # just to simplify negative comparisons later
        # we generate multiple replay sequences on train data with different visit frequencies
        # to generate more diverse training data
        print("Start generating training data")
        for visit_frequency in range(1, 10):
            print(visit_frequency)
            train_replay_sequence = generate_replay_sequence(train_data, visit_frequency)
            # we group fingerprints by user id
            user_id_to_fps = dict()
            for elt in train_replay_sequence:
                counter = int(elt[0].split("_")[0])
                fingerprint = counter_to_fingerprint[counter]
                if fingerprint.getId() not in user_id_to_fps:
                    user_id_to_fps[fingerprint.getId()] = []
                user_id_to_fps[fingerprint.getId()].append(fingerprint)

            # we generate the training data
            X, y = [], []
            attributes = sorted(fingerprint_dataset[0].val_attributes.keys())
            for user_id in user_id_to_fps:
                previous_fingerprint = None
                for fingerprint in user_id_to_fps[user_id]:
                    if previous_fingerprint is not None:
                        x_row, y_row = compute_similarity_fingerprint(fingerprint, previous_fingerprint, att_ml,
                                                                      train_mode=True)
                        X.append(x_row)
                        y.append(y_row)
                    previous_fingerprint = fingerprint

            # we compute negative rows
            for user_id in user_id_to_fps:
                for fp1 in user_id_to_fps[user_id]:
                    try:
                        compare_with_id = index_to_user_id[random.randint(0, len(user_id_to_fps))]
                        compare_with_fp = random.randint(0, len(user_id_to_fps[compare_with_id]))
                        fp2 = user_id_to_fps[compare_with_id][compare_with_fp]
                        x_row, y_row = compute_similarity_fingerprint(fp1, fp2, att_ml, train_mode=True)
                        X.append(x_row)
                        y.append(y_row)
                    except:
                        pass

        print("Start training model")
        model = RandomForestClassifier(n_jobs=4)
        print("Training data: %d" % len(X))
        model.fit(X, y)
        print("Model trained")
        joblib.dump(model, model_path)
        print("model saved at: %s" % model_path)

    return model


def ml_based(fingerprint_unknown, user_id_to_fps, counter_to_fingerprint, model, lambda_threshold):
    forbidden_changes = [
        Fingerprint.LOCAL_JS,
        Fingerprint.DNT_JS,
        Fingerprint.COOKIES_JS
    ]

    allowed_changes_with_sim = [
        Fingerprint.USER_AGENT_HTTP,
        Fingerprint.VENDOR,
        Fingerprint.RENDERER,
        Fingerprint.PLUGINS_JS,
        Fingerprint.LANGUAGE_HTTP,
        Fingerprint.ACCEPT_HTTP
    ]

    allowed_changes = [
        Fingerprint.RESOLUTION_JS,
        Fingerprint.ENCODING_HTTP,

    ]

    not_to_test = set([Fingerprint.PLATFORM_FLASH,
                       Fingerprint.PLATFORM_INCONSISTENCY,
                       Fingerprint.PLATFORM_JS,
                       Fingerprint.PLUGINS_JS_HASHED,
                       Fingerprint.SESSION_JS,
                       Fingerprint.IE_DATA_JS,
                       Fingerprint.ADDRESS_HTTP,
                       Fingerprint.BROWSER_FAMILY,
                       Fingerprint.COOKIES_JS,
                       Fingerprint.DNT_JS,
                       Fingerprint.END_TIME,
                       Fingerprint.FONTS_FLASH_HASHED,
                       Fingerprint.GLOBAL_BROWSER_VERSION,
                       Fingerprint.LANGUAGE_FLASH,
                       Fingerprint.LANGUAGE_INCONSISTENCY,
                       Fingerprint.LOCAL_JS,
                       Fingerprint.MINOR_BROWSER_VERSION,
                       Fingerprint.MAJOR_BROWSER_VERSION,
                       Fingerprint.NB_FONTS,
                       Fingerprint.NB_PLUGINS,
                       Fingerprint.COUNTER,
                       Fingerprint.OS,
                       Fingerprint.ACCEPT_HTTP,
                       Fingerprint.CONNECTION_HTTP,
                       Fingerprint.ENCODING_HTTP,
                       Fingerprint.RESOLUTION_FLASH,
                       Fingerprint.TIMEZONE_JS,
                       Fingerprint.VENDOR,
                       ])

    att_ml = set(fingerprint_unknown.val_attributes.keys())
    att_ml = sorted([x for x in att_ml if x not in not_to_test])

    ip_allowed = False
    candidates = list()
    exact_matching = list()
    prediction = None
    for user_id in user_id_to_fps:
        for counter_str in user_id_to_fps[user_id]:
            counter_known = int(counter_str.split("_")[0])
            fingerprint_known = counter_to_fingerprint[counter_known]

            # check fingerprint full hash for exact matching
            if fingerprint_known.hash == fingerprint_unknown.hash:
                exact_matching.append((counter_str, None, user_id))
            elif len(exact_matching) < 1 and fingerprint_known.constant_hash == \
                    fingerprint_unknown.constant_hash:
                # we make the comparison only if same os/browser/platform
                if fingerprint_known.val_attributes[Fingerprint.GLOBAL_BROWSER_VERSION] > \
                        fingerprint_unknown.val_attributes[Fingerprint.GLOBAL_BROWSER_VERSION]:
                    continue

                forbidden_change_found = False
                for attribute in forbidden_changes:
                    if fingerprint_known.val_attributes[attribute] != \
                            fingerprint_unknown.val_attributes[attribute]:
                        forbidden_change_found = True
                        break

                if forbidden_change_found:
                    continue

                candidates.append((counter_str, None, user_id))

    if len(exact_matching) > 0:
        if len(exact_matching) == 1 or candidates_have_same_id(exact_matching):
            return exact_matching[0][2]
    elif len(candidates) > 0:
        # in this case we apply ML
        data = []
        attributes = sorted(fingerprint_unknown.val_attributes.keys())
        new_candidates = []
        for elt in candidates:
            counter = int(elt[0].split("_")[0])
            fingerprint_known = counter_to_fingerprint[counter]
            x_row, _ = compute_similarity_fingerprint(fingerprint_unknown,
                                                      fingerprint_known,
                                                      att_ml, train_mode=False)
            if x_row is not None:
                data.append(x_row)
                new_candidates.append(elt)

        if len(new_candidates) > 0:
            predictions_model = model.predict_proba(data)
            predictions_model = 1.0 - predictions_model
            nearest = (-predictions_model[:, 0]).argsort()[:3]

            max_nearest = 1
            second_proba = None
            for i in range(1, len(nearest)):
                if predictions_model[nearest[i], 0] != predictions_model[nearest[0], 0]:
                    max_nearest = i
                    second_proba = predictions_model[nearest[i], 0]
                    break
            nearest = nearest[:max_nearest]

            diff_enough = True
            if second_proba is not None and predictions_model[nearest[0], 0] < second_proba + 0.1: # 0.1 = diff parameter
                diff_enough = False

            if diff_enough and predictions_model[nearest[0], 0] > lambda_threshold and candidates_have_same_id(
                    [candidates[x] for x in nearest]):
                prediction = new_candidates[nearest[0]][2]

    if prediction is None:
        prediction = generate_new_id()

    return prediction


def load_scenario_result(filename):
    """
        Loads and returns a scenario result from disk
    """
    scenario_result = []
    with open(filename, "r") as f:
        for line in f:
            l_split = line.split(",")
            scenario_result.append((l_split[0], l_split[1]))

    return scenario_result


def compute_ownership(fingerprints):
    real_user_id_to_count = dict()
    for fingerprint in fingerprints:
        if fingerprint.getId() in real_user_id_to_count:
            real_user_id_to_count[fingerprint.getId()] += 1
        else:
            real_user_id_to_count[fingerprint.getId()] = 1

    max_key = max(real_user_id_to_count, key=real_user_id_to_count.get)
    return float(real_user_id_to_count[max_key] / len(fingerprints)), max_key


def find_longest_chain(real_user_id, real_id_to_assigned_ids, assigned_ids_to_fingerprint):
    """
        For a given user id, tries to find its longest chain
    """
    assigned_ids = real_id_to_assigned_ids[real_user_id]
    assigned_id_to_count = dict()
    for assigned_id in assigned_ids:
        tmp_count = 0
        for fingerprint in assigned_ids_to_fingerprint[assigned_id]:
            if fingerprint.getId() == real_user_id:
                tmp_count += 1

        assigned_id_to_count[assigned_id] = tmp_count

    return max(assigned_id_to_count.items(), key=lambda x: x[1])[1]


def analyse_scenario_result(scenario_result, fingerprint_dataset,
                            fileres1="./results/res1.csv",
                            fileres2="./results/res2.csv"):
    """
        Performs an analysis of a scenario result
    """
    counter_to_fingerprint = dict()
    real_user_id_tp_nb_fps = dict()
    real_ids = set()
    aareal_user_id_to_fps = dict()
    for fingerprint in fingerprint_dataset:
        counter_to_fingerprint[fingerprint.getCounter()] = fingerprint
        real_ids.add(fingerprint.getId())
        if fingerprint.getId() not in aareal_user_id_to_fps:
            aareal_user_id_to_fps[fingerprint.getId()] = 1
        else:
            aareal_user_id_to_fps[fingerprint.getId()] += 1

    # we map new assigned ids to real ids in database
    assigned_ids = set()
    real_id_to_assigned_ids = dict()
    assigned_id_to_real_ids = dict()
    assigned_id_to_fingerprints = dict()
    for elt in scenario_result:
        counter = int(elt[0].split("_")[0])
        assigned_id = elt[1]
        assigned_ids.add(assigned_id)
        real_db_id = counter_to_fingerprint[counter].getId()
        if real_db_id not in real_user_id_tp_nb_fps:
            real_user_id_tp_nb_fps[real_db_id] = 1
        else:
            real_user_id_tp_nb_fps[real_db_id] += 1

        if real_db_id not in real_id_to_assigned_ids:
            real_id_to_assigned_ids[real_db_id] = set()
        real_id_to_assigned_ids[real_db_id].add(assigned_id)

        if assigned_id not in assigned_id_to_real_ids:
            assigned_id_to_real_ids[assigned_id] = set()
            assigned_id_to_fingerprints[assigned_id] = []

        assigned_id_to_real_ids[assigned_id].add(counter_to_fingerprint[counter].getId())
        assigned_id_to_fingerprints[assigned_id].append(counter_to_fingerprint[counter])

    with open(fileres1, "w") as f:
        f.write("%s,%s,%s,%s,%s\n" % ("real_id", "nb_assigned_ids", "nb_original_fp", "ratio", "max_chain"))
        # don't iterate over reals_ids since some fps don't have end date and are not present
        for real_id in real_id_to_assigned_ids:
            max_chain = find_longest_chain(real_id, real_id_to_assigned_ids, assigned_id_to_fingerprints)
            ratio_stats = real_user_id_tp_nb_fps[real_id] / len(real_id_to_assigned_ids[real_id])
            f.write("%s,%d,%d,%f,%d\n" % (real_id,
                                          len(real_id_to_assigned_ids[real_id]),
                                          real_user_id_tp_nb_fps[real_id],
                                          ratio_stats, max_chain)
                    )

    with open(fileres2, "w") as f:
        f.write("%s,%s,%s,%s,%s\n" % ("assigned_id", "nb_assigned_ids", "nb_fingerprints",
                                      "ownership", "id_ownership"))
        for assigned_id in assigned_id_to_real_ids:
            ownership, ownsership_id = compute_ownership(assigned_id_to_fingerprints[assigned_id])
            f.write("%s,%d,%d,%f,%s\n" % (assigned_id, len(assigned_id_to_real_ids[assigned_id]),
                                          len(assigned_id_to_fingerprints[assigned_id]), ownership,
                                          ownsership_id))


def compute_distance_top_left(tpr, fp):
    return (0 - fp) * (0 - fp) + (1 - tpr) * (1 - tpr)


def optimize_lambda(fingerprint_dataset, train_data, test_data):
    counter_to_fingerprint = dict()
    index_to_user_id = dict()
    user_ids = set()
    index = 0
    for fingerprint in fingerprint_dataset:
        counter_to_fingerprint[fingerprint.getCounter()] = fingerprint
        if fingerprint.getId() not in user_ids:
            user_ids.add(fingerprint.getId())
            index_to_user_id[index] = fingerprint.getId()
            index += 1

    print("Start generating training data")
    for visit_frequency in range(1, 10):
        print(visit_frequency)
        train_replay_sequence = generate_replay_sequence(train_data, visit_frequency)
        # we group fingerprints by user id
        user_id_to_fps = dict()
        for elt in train_replay_sequence:
            counter = int(elt[0].split("_")[0])
            fingerprint = counter_to_fingerprint[counter]
            if fingerprint.getId() not in user_id_to_fps:
                user_id_to_fps[fingerprint.getId()] = []
            user_id_to_fps[fingerprint.getId()].append(fingerprint)

        # we generate the training data
        X, y = [], []
        attributes = sorted(fingerprint_dataset[0].val_attributes.keys())
        for user_id in user_id_to_fps:
            previous_fingerprint = None
            for fingerprint in user_id_to_fps[user_id]:
                if previous_fingerprint is not None:
                    x_row, y_row = compute_similarity_fingerprint(fingerprint, previous_fingerprint, attributes,
                                                                  train_mode=True)
                    X.append(x_row)
                    y.append(y_row)
                previous_fingerprint = fingerprint

        # we compute negative rows
        for user_id in user_id_to_fps:
            for fp1 in user_id_to_fps[user_id]:
                try:
                    compare_with_id = index_to_user_id[random.randint(0, len(user_id_to_fps))]
                    compare_with_fp = random.randint(0, len(user_id_to_fps[compare_with_id])-1)
                    fp2 = user_id_to_fps[compare_with_id][compare_with_fp]
                    x_row, y_row = compute_similarity_fingerprint(fp1, fp2, attributes, train_mode=True)
                    X.append(x_row)
                    y.append(y_row)
                except:
                    print("error")
                    pass

    model = RandomForestClassifier(n_jobs=4)
    print("Training data: %d" % len(X))
    model.fit(X, y)
    print("Finished training")

    y_true = []
    y_scores = []
    for visit_frequency in range(1, 20):
        print(visit_frequency)
        train_replay_sequence = generate_replay_sequence(test_data, visit_frequency)
        # we group fingerprints by user id
        user_id_to_fps = dict()
        for elt in train_replay_sequence:
            counter = int(elt[0].split("_")[0])
            fingerprint = counter_to_fingerprint[counter]
            if fingerprint.getId() not in user_id_to_fps:
                user_id_to_fps[fingerprint.getId()] = []
            user_id_to_fps[fingerprint.getId()].append(fingerprint)

        attributes = sorted(fingerprint_dataset[0].val_attributes.keys())
        x_rows = []
        for user_id in user_id_to_fps:
            previous_fingerprint = None
            for fingerprint in user_id_to_fps[user_id]:
                if previous_fingerprint is not None:
                    x_row, y_row = compute_similarity_fingerprint(fingerprint, previous_fingerprint, attributes, True)
                    x_rows.append(x_row)
                    y_true.append(1)
                previous_fingerprint = fingerprint

        for user_id in user_id_to_fps:
            for fp1 in user_id_to_fps[user_id]:
                try:
                    compare_with_id = index_to_user_id[random.randint(0, len(user_id_to_fps))]
                    compare_with_fp = random.randint(0, len(user_id_to_fps[compare_with_id]))
                    fp2 = user_id_to_fps[compare_with_id][compare_with_fp]
                    x_row, y_row = compute_similarity_fingerprint(fp1, fp2, attributes)
                    x_rows.append(x_row)
                    y_true.append(0)
                except:
                    pass
        predictions = model.predict_proba(x_rows)
        for prediction in predictions:
            y_scores.append(prediction[1])

    fpr, tpr, thresholds = metrics.roc_curve(y_true, y_scores, pos_label=1)
    min_indice = 0
    min_distance = compute_distance_top_left(tpr[0], fpr[0])
    for i in range(1, len(fpr)):
        distance = compute_distance_top_left(tpr[i], fpr[i])
        if distance < min_distance:
            min_indice = i
            min_distance = distance

    print("best point")
    print("%f, %f, %f" % (fpr[min_indice], tpr[min_indice], thresholds[min_indice]))
    plt.figure()
    lw = 2
    plt.plot(fpr, tpr, color='darkorange', lw=lw)
    plt.plot([0, 1], [0, 1], color='navy', lw=lw, linestyle='--')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate', fontsize=15)
    plt.ylabel('True Positive Rate', fontsize=15)
    plt.savefig("./lambda_optim.pdf")
    plt.show()


def collect_results(result):
    results.extend(result)


def simple_catch(fn, max_diff, nb_cmp_per_id, conn, attributes):
    try:
        fn(max_diff, nb_cmp_per_id, conn, attributes)
    except Exception as e:
        print(e)


def candidates_have_same_id_bench(candidate_list):
    """
        Returns True if all candidates have the same id
        Else False
    """
    lf = [x for x in candidate_list if x is not None]
    if len(lf) == 0:
        return False
    return not any(not x for x in [y[0] == lf[0][0] for y in lf])

def parallel_pipe_task_rules_f(max_diff, nb_cmp_per_id, conn, attributes):
    forbidden_changes = [
        Fingerprint.LOCAL_JS,
        Fingerprint.DNT_JS,
        Fingerprint.COOKIES_JS
    ]

    allowed_changes_with_sim = [
        Fingerprint.USER_AGENT_HTTP,
        Fingerprint.VENDOR,
        Fingerprint.RENDERER,
        Fingerprint.PLUGINS_JS,
        Fingerprint.LANGUAGE_HTTP,
        Fingerprint.ACCEPT_HTTP
    ]

    allowed_changes = [
        Fingerprint.RESOLUTION_JS,
        Fingerprint.ENCODING_HTTP,

    ]
    nb_cmp_per_id = 2
    user_id_to_fps = dict()
    constant_hash_to_user_id = dict()
    msg = "CONTINUE"
    while msg == "CONTINUE":
        fp_to_add = conn.recv()
        if fp_to_add == "STOP":
            break

        if fp_to_add.constant_hash not in constant_hash_to_user_id:
            constant_hash_to_user_id[fp_to_add.constant_hash] = set()

        constant_hash_to_user_id[fp_to_add.constant_hash].add(fp_to_add.getId())

        if fp_to_add.getId() in user_id_to_fps:
            user_id_to_fps[fp_to_add.getId()].append(fp_to_add)
        else:
            user_id_to_fps[fp_to_add.getId()] = list()
            user_id_to_fps[fp_to_add.getId()].append(fp_to_add)

        msg = conn.recv()

    conn.send(len(user_id_to_fps))
    print("Finished collecting fps")

    msg = "CONTINUE"
    print("Start classification process")
    avg_nb_cmp = 0
    total_nb = 0
    while msg == "CONTINUE":
        msg = conn.recv()
        if msg != "CONTINUE":
            break
        Xp = []
        fingerprint_unknown = conn.recv()
        row_index_to_counter = dict()

        candidates = list()
        exact_matching = list()
        prediction = None
        if fingerprint_unknown.constant_hash not in constant_hash_to_user_id:
            prediction = (generate_new_id(), 1.0)
        else:
            for user_id in constant_hash_to_user_id[fingerprint_unknown.constant_hash]:
                for fingerprint_known in user_id_to_fps[user_id]:
                    if fingerprint_known.hash == fingerprint_unknown.hash:
                        # either we look if there are multiple users that match
                        # in that case we create new id
                        # or we assign randomly?
                        exact_matching.append((fingerprint_known, None, user_id))
                    elif len(exact_matching) < 1 and fingerprint_known.constant_hash == \
                            fingerprint_unknown.constant_hash:
                        # we make the comparison only if same os/browser/platform
                        if fingerprint_known.val_attributes[Fingerprint.GLOBAL_BROWSER_VERSION] > \
                                fingerprint_unknown.val_attributes[Fingerprint.GLOBAL_BROWSER_VERSION]:
                            continue

                        if fingerprint_known.hasFlashActivated() and fingerprint_unknown.hasFlashActivated() and \
                                not fingerprint_known.areFontsSubset(fingerprint_unknown):
                            continue

                        forbidden_change_found = False
                        for attribute in forbidden_changes:
                            if fingerprint_known.val_attributes[attribute] != \
                                    fingerprint_unknown.val_attributes[attribute]:
                                forbidden_change_found = True
                                break

                        if forbidden_change_found:
                            continue

                        nb_changes = 0
                        changes = []
                        # we allow at most 2 changes, then we check for similarity
                        for attribute in allowed_changes_with_sim:
                            if fingerprint_known.val_attributes[attribute] != \
                                    fingerprint_unknown.val_attributes[attribute]:
                                changes.append(attribute)
                                nb_changes += 1

                            if nb_changes > 2:
                                break

                        if nb_changes > 2:
                            continue

                        sim_too_low = False
                        for attribute in changes:
                            if ratio(fingerprint_known.val_attributes[attribute],
                                     fingerprint_unknown.val_attributes[attribute]) < 0.75:
                                sim_too_low = True
                                break
                        if sim_too_low:
                            continue

                        nb_allowed_changes = 0
                        for attribute in allowed_changes:
                            if fingerprint_known.val_attributes[attribute] != \
                                    fingerprint_unknown.val_attributes[attribute]:
                                nb_allowed_changes += 1

                            if nb_allowed_changes > 1:
                                break

                        if nb_allowed_changes > 1:
                            continue

                        total_nb_changes = nb_allowed_changes + nb_changes
                        if total_nb_changes == 0:
                            exact_matching.append((fingerprint_known, None, user_id))
                        else:
                            candidates.append((fingerprint_known, total_nb_changes, user_id))

            if len(exact_matching) > 0:
                if len(exact_matching) == 1 or candidates_have_same_id(exact_matching):
                    prediction = (exact_matching[0][2], 0)
            else:
                if len(candidates) == 1 or candidates_have_same_id(candidates):
                    prediction = (candidates[0][2], candidates[0][2])

        res = prediction
        conn.send(res)

        if prediction is None:
            prediction = (generate_new_id(), 1.0)

        # we wait to know if we keep or discard fp test on our node
        keep_fp_test = conn.recv()
        if keep_fp_test == "KEEP":
            fingerprint_unknown.val_attributes["id"] = prediction[0]
            if fingerprint_unknown.constant_hash not in constant_hash_to_user_id:
                constant_hash_to_user_id[fingerprint_unknown.constant_hash] = set()

            constant_hash_to_user_id[fingerprint_unknown.constant_hash].add(prediction[0])
            if not fingerprint_unknown.getId() in user_id_to_fps:
                user_id_to_fps[fingerprint_unknown.getId()] = list()
            elif len(user_id_to_fps[fingerprint_unknown.getId()]) == nb_cmp_per_id:
                # if the list contains already 3 elements we remove the
                # oldest one
                user_id_to_fps[fingerprint_unknown.getId()].pop(0)

            # Finally we add the new fingerprint
            user_id_to_fps[fingerprint_unknown.getId()].append(fingerprint_unknown)

    print("avg nb cmp : %f" % float(avg_nb_cmp / total_nb))

    return [float(avg_nb_cmp / total_nb)]

def parallel_pipe_task_ml_f(max_diff, nb_cmp_per_id, conn, attributes):
    forbidden_changes = [
        Fingerprint.LOCAL_JS,
        Fingerprint.DNT_JS,
        Fingerprint.COOKIES_JS
    ]

    allowed_changes_with_sim = [
        Fingerprint.USER_AGENT_HTTP,
        Fingerprint.VENDOR,
        Fingerprint.RENDERER,
        Fingerprint.PLUGINS_JS,
        Fingerprint.LANGUAGE_HTTP,
        Fingerprint.ACCEPT_HTTP
    ]

    allowed_changes = [
        Fingerprint.RESOLUTION_JS,
        Fingerprint.ENCODING_HTTP,

    ]
    nb_cmp_per_id = 2
    user_id_to_fps = dict()
    constant_hash_to_user_id = dict()
    msg = "CONTINUE"
    while msg == "CONTINUE":
        fp_to_add = conn.recv()
        if fp_to_add == "STOP":
            break

        if fp_to_add.constant_hash not in constant_hash_to_user_id:
            constant_hash_to_user_id[fp_to_add.constant_hash] = set()

        constant_hash_to_user_id[fp_to_add.constant_hash].add(fp_to_add.getId())

        if fp_to_add.getId() in user_id_to_fps:
            user_id_to_fps[fp_to_add.getId()].append(fp_to_add)
        else:
            user_id_to_fps[fp_to_add.getId()] = list()
            user_id_to_fps[fp_to_add.getId()].append(fp_to_add)

        msg = conn.recv()

    conn.send(len(user_id_to_fps))
    print("Finished collecting fps")

    # Real classification process starts here
    model = joblib.load('./data/my_ml_model')
    msg = "CONTINUE"
    print("Start classification process")
    avg_nb_cmp = 0
    total_nb = 0
    while msg == "CONTINUE":
        msg = conn.recv()
        if msg != "CONTINUE":
            break
        Xp = []
        fingerprint_unknown = conn.recv()
        row_index_to_counter = dict()

        candidates = list()
        exact_matching = list()
        prediction = None
        if fingerprint_unknown.constant_hash not in constant_hash_to_user_id:
            prediction = (generate_new_id(), 1.0)
        else:
            for user_id in constant_hash_to_user_id[fingerprint_unknown.constant_hash]:
                for fingerprint_known in user_id_to_fps[user_id]:
                    # check fingerprint full hash for exact matching
                    if fingerprint_known.hash == fingerprint_unknown.hash:
                        exact_matching.append((fingerprint_known, None, user_id))
                    elif len(exact_matching) < 1:
                        # we make the comparison only if same os/browser/platform
                        if fingerprint_known.val_attributes[Fingerprint.GLOBAL_BROWSER_VERSION] > \
                                fingerprint_unknown.val_attributes[Fingerprint.GLOBAL_BROWSER_VERSION]:
                            continue

                        forbidden_change_found = False
                        for attribute in forbidden_changes:
                            if fingerprint_known.val_attributes[attribute] != \
                                    fingerprint_unknown.val_attributes[attribute]:
                                forbidden_change_found = True
                                break

                        if forbidden_change_found:
                            continue

                        candidates.append((fingerprint_known, None, user_id))

            prediction = None
            if len(exact_matching) > 0:
                if len(exact_matching) == 1 or candidates_have_same_id(exact_matching):
                    prediction = (exact_matching[0][2], 1.1)
            elif len(candidates) > 0:
                # in this case we apply ML
                data = []
                new_candidates = []
                for elt in candidates:
                    fingerprint_known = elt[0]
                    x_row, _ = compute_similarity_fingerprint(fingerprint_unknown,
                                                              fingerprint_known,
                                                              attributes, train_mode=False)
                    if x_row is not None:
                        data.append(x_row)
                        new_candidates.append(elt)

                if len(new_candidates) > 0:
                    predictions_model = model.predict_proba(data)
                    predictions_model = 1.0 - predictions_model
                    nearest = (-predictions_model[:, 0]).argsort()[:2]

                    if predictions_model[nearest[0], 0] > 0.93:
                        # we check is one of them has the same IP address
                        if len(predictions_model) > 1 and predictions_model[nearest[0], 0] > \
                                        predictions_model[nearest[1], 0] + 0.10:
                            prediction = (new_candidates[nearest[0]][2], predictions_model[nearest[0], 0])
                        elif candidates_have_same_id([candidates[x] for x in nearest]):
                            # we check if all the candidates have the same id
                            prediction = (new_candidates[nearest[0]][2], predictions_model[nearest[0], 0])

        res = prediction
        conn.send(res)

        if prediction is None:
            prediction = (generate_new_id(), 1.0)

        # we wait to know if we keep or discard fp test on our node
        keep_fp_test = conn.recv()
        if keep_fp_test == "KEEP":
            fingerprint_unknown.val_attributes["id"] = prediction[0]
            if fingerprint_unknown.constant_hash not in constant_hash_to_user_id:
                constant_hash_to_user_id[fingerprint_unknown.constant_hash] = set()

            constant_hash_to_user_id[fingerprint_unknown.constant_hash].add(prediction[0])
            if not fingerprint_unknown.getId() in user_id_to_fps:
                user_id_to_fps[fingerprint_unknown.getId()] = list()
            elif len(user_id_to_fps[fingerprint_unknown.getId()]) == nb_cmp_per_id:
                # if the list contains already 3 elements we remove the
                # oldest one
                user_id_to_fps[fingerprint_unknown.getId()].pop(0)

            # Finally we add the new fingerprint
            user_id_to_fps[fingerprint_unknown.getId()].append(fingerprint_unknown)

    print("avg nb cmp : %f" % float(avg_nb_cmp / total_nb))

    return [float(avg_nb_cmp / total_nb)]

def benchmark_parallel_f_ml(fn, cur, nb_fps_query, nb_cores):
    NB_PROCESSES = nb_cores
    MAX_DIFF = 4
    NB_CMP_PER_ID = 2

    seed = 42
    random.seed(seed)
    nb_fps_query = int(nb_fps_query / 50)

    cur.execute("SELECT *, NULL as canvasJS FROM extensionDataScheme LIMIT 0," + str(nb_fps_query))
    fps = cur.fetchall()

    attributes = Fingerprint.INFO_ATTRIBUTES + Fingerprint.HTTP_ATTRIBUTES + \
                 Fingerprint.JAVASCRIPT_ATTRIBUTES + Fingerprint.FLASH_ATTRIBUTES

    tmp_fp = Fingerprint(attributes, fps[40])

    not_to_test = set([Fingerprint.PLATFORM_FLASH,
                       Fingerprint.PLATFORM_INCONSISTENCY,
                       Fingerprint.PLATFORM_JS,
                       Fingerprint.PLUGINS_JS_HASHED,
                       Fingerprint.SESSION_JS,
                       Fingerprint.IE_DATA_JS,
                       Fingerprint.ADDRESS_HTTP,
                       Fingerprint.BROWSER_FAMILY,
                       Fingerprint.COOKIES_JS,
                       Fingerprint.DNT_JS,
                       Fingerprint.END_TIME,
                       Fingerprint.FONTS_FLASH_HASHED,
                       Fingerprint.GLOBAL_BROWSER_VERSION,
                       Fingerprint.LANGUAGE_FLASH,
                       Fingerprint.LANGUAGE_INCONSISTENCY,
                       Fingerprint.LOCAL_JS,
                       Fingerprint.MINOR_BROWSER_VERSION,
                       Fingerprint.MAJOR_BROWSER_VERSION,
                       Fingerprint.NB_FONTS,
                       Fingerprint.NB_PLUGINS,
                       Fingerprint.COUNTER,
                       Fingerprint.OS,
                       Fingerprint.ACCEPT_HTTP,
                       Fingerprint.CONNECTION_HTTP,
                       Fingerprint.ENCODING_HTTP,
                       Fingerprint.RESOLUTION_FLASH,
                       Fingerprint.TIMEZONE_JS,
                       Fingerprint.VENDOR,
                       ])

    att_ml = set(tmp_fp.val_attributes.keys())
    att_ml = sorted([x for x in att_ml if x not in not_to_test])
    print(att_ml)

    #  master node initialization
    # we launch the pool of processes
    p = Pool(processes=NB_PROCESSES)
    parent_conn_list = []
    child_conn_list = []
    for i in range(0, NB_PROCESSES):
        parent_conn, child_conn = Pipe()
        parent_conn_list.append(parent_conn)
        child_conn_list.append(child_conn)
        p.apply_async(simple_catch,
                      args=(fn, MAX_DIFF,
                            NB_CMP_PER_ID,
                            child_conn, att_ml))

    # We send the fingerprints on the processes
    total_nb_ids = 0
    fp_constant_hash_to_next_node = dict()

    for fp in fps:
        for i in range(0, 50):
            new_user_id = fp["id"]
            if i % 2 == 0:
                new_user_id = generate_new_id()
                total_nb_ids += 1

            new_canvas_hashed = fp["canvasJSHashed"][:-4] + \
                                str(random.randint(0, 2000))
            new_timezone = str(random.randint(0, 2000))

            fp["id"] = new_user_id
            fp["canvasHashed"] = new_canvas_hashed
            fp["timezoneJS"] = new_timezone
            fp_mutated = Fingerprint(attributes, fp)

            if fp_mutated.constant_hash not in fp_constant_hash_to_next_node:
                fp_constant_hash_to_next_node[fp_mutated.constant_hash] = 0

            if i % 2 == 0:
                # we change every two fingerprints since its
                # the number of fingerprints per user
                fp_constant_hash_to_next_node[fp_mutated.constant_hash] = (fp_constant_hash_to_next_node[
                                                                               fp_mutated.constant_hash] + 1) % NB_PROCESSES

            node_to_send = fp_constant_hash_to_next_node[fp_mutated.constant_hash]
            parent_conn_list[node_to_send].send(fp_mutated)
            parent_conn_list[node_to_send].send("CONTINUE")

    print("There are %d ids" % total_nb_ids)

    for conn in parent_conn_list:
        conn.send("STOP")
        nb_ids = conn.recv()
        print("There are %d different ids on each nodes" % nb_ids)

    # Fingerprints have been distributed, we can start to measure
    print("Start 2nd fake sql query")
    cur.execute("SELECT *, NULL as canvasJS FROM extensionDataScheme LIMIT 1000, 2000")
    print("Finish 2nd fake sql query")
    fps = cur.fetchall()
    nb_iter = 0
    limit_iter = 100
    if NB_PROCESSES < 8:
        limit_iter = 30
    times = []
    index_to_add = 0
    for fp in fps:
        print("Iter %d" % nb_iter)
        if nb_iter == limit_iter:
            for conn in parent_conn_list:
                conn.send("STOP")
            break
        else:
            for conn in parent_conn_list:
                conn.send("CONTINUE")

        s = string.ascii_uppercase + string.digits
        new_user_id = ''.join(random.sample(s, 10))

        new_canvas_hashed = fp["canvasJSHashed"][:-4] + \
                            str(random.randint(0, 2000))
        new_timezone = str(random.randint(0, 2000))

        fp["id"] = new_user_id
        fp["canvasHashed"] = new_canvas_hashed
        fp["timezoneJS"] = new_timezone
        fp_mutated = Fingerprint(attributes, fp)

        start = time.time()
        for conn in parent_conn_list:
            conn.send(fp_mutated)

        node_to_prediction = list()
        exact_matching = list()
        for conn in parent_conn_list:
            node_to_prediction.append(conn.recv())
            if node_to_prediction[-1] is not None and node_to_prediction[-1][1] == 1.1:
                exact_matching.append(node_to_prediction[-1])

        max_index = 0
        for i in range(1, len(node_to_prediction)):
            if node_to_prediction[i] is not None:
                if node_to_prediction[max_index] is None:
                    max_index = i
                elif node_to_prediction[i][1] > node_to_prediction[max_index][1]:
                    max_index = i

        if node_to_prediction.count(None) == len(node_to_prediction):
            prediction = "None"
        elif len(exact_matching) == 1 or candidates_have_same_id_bench(exact_matching):
            prediction = (exact_matching[0][2], 1.1)
        # the diff parameter is implicit since it has been applied on slave nodes
        elif node_to_prediction[max_index][1] > 0.98 and candidates_have_same_id_bench(node_to_prediction):
            prediction = node_to_prediction[max_index]
        else:
            prediction = "None"

        # doens't matter for the benchmark
        node_to_add_fp_test = max_index

        # then we communicate our decision to all of the nodes/processes
        for i in range(0, NB_PROCESSES):
            if i == node_to_add_fp_test:
                parent_conn_list[i].send("KEEP")
            else:
                parent_conn_list[i].send("DISCARD")

        end = time.time()
        times.append(end - start)
        print(end - start)

        nb_iter += 1

    p.close()
    p.terminate()
    p.join()
    print(results)

    times = np.asarray(times)
    print("avg time : %f" % np.mean(times))
    print("min time: %f" % np.min(times))
    print("max time: %f" % np.max(times))
    print("25pct : %f" % np.percentile(times, 25))
    print("50pct : %f" % np.percentile(times, 50))
    print("75pct : %f" % np.percentile(times, 75))
    return (np.mean(times),
            np.min(times),
            np.max(times),
            np.percentile(times, 25),
            np.percentile(times, 50),
            np.percentile(times, 75)
            )

def benchmark_parallel_f_rules(fn, cur, nb_fps_query, nb_cores):
    NB_PROCESSES = nb_cores
    MAX_DIFF = 4
    NB_CMP_PER_ID = 2

    seed = 42
    random.seed(seed)
    nb_fps_query = int(nb_fps_query / 50)

    cur.execute("SELECT *, NULL as canvasJS FROM extensionDataScheme LIMIT 0," + str(nb_fps_query))
    fps = cur.fetchall()

    attributes = Fingerprint.INFO_ATTRIBUTES + Fingerprint.HTTP_ATTRIBUTES + \
                 Fingerprint.JAVASCRIPT_ATTRIBUTES + Fingerprint.FLASH_ATTRIBUTES

    tmp_fp = Fingerprint(attributes, fps[40])

    not_to_test = set([Fingerprint.PLATFORM_FLASH,
                       Fingerprint.PLATFORM_INCONSISTENCY,
                       Fingerprint.PLATFORM_JS,
                       Fingerprint.PLUGINS_JS_HASHED,
                       Fingerprint.SESSION_JS,
                       Fingerprint.IE_DATA_JS,
                       Fingerprint.ADDRESS_HTTP,
                       Fingerprint.BROWSER_FAMILY,
                       Fingerprint.COOKIES_JS,
                       Fingerprint.DNT_JS,
                       Fingerprint.END_TIME,
                       Fingerprint.FONTS_FLASH_HASHED,
                       Fingerprint.GLOBAL_BROWSER_VERSION,
                       Fingerprint.LANGUAGE_FLASH,
                       Fingerprint.LANGUAGE_INCONSISTENCY,
                       Fingerprint.LOCAL_JS,
                       Fingerprint.MINOR_BROWSER_VERSION,
                       Fingerprint.MAJOR_BROWSER_VERSION,
                       Fingerprint.NB_FONTS,
                       Fingerprint.NB_PLUGINS,
                       Fingerprint.COUNTER,
                       Fingerprint.OS,
                       Fingerprint.ACCEPT_HTTP,
                       Fingerprint.CONNECTION_HTTP,
                       Fingerprint.ENCODING_HTTP,
                       Fingerprint.RESOLUTION_FLASH,
                       Fingerprint.TIMEZONE_JS,
                       Fingerprint.VENDOR,
                       ])

    att_ml = set(tmp_fp.val_attributes.keys())
    att_ml = sorted([x for x in att_ml if x not in not_to_test])
    print(att_ml)

    #  master node initialization
    # we launch the pool of processes
    p = Pool(processes=NB_PROCESSES)
    parent_conn_list = []
    child_conn_list = []
    for i in range(0, NB_PROCESSES):
        parent_conn, child_conn = Pipe()
        parent_conn_list.append(parent_conn)
        child_conn_list.append(child_conn)
        p.apply_async(simple_catch,
                      args=(fn, MAX_DIFF,
                            NB_CMP_PER_ID,
                            child_conn, att_ml))

    # We send the fingerprints on the processes
    total_nb_ids = 0
    fp_constant_hash_to_next_node = dict()

    for fp in fps:
        for i in range(0, 50):
            new_user_id = fp["id"]
            if i % 2 == 0:
                new_user_id = generate_new_id()
                total_nb_ids += 1

            new_canvas_hashed = fp["canvasJSHashed"][:-4] + \
                                str(random.randint(0, 2000))
            new_timezone = str(random.randint(0, 2000))

            fp["id"] = new_user_id
            fp["canvasHashed"] = new_canvas_hashed
            fp["timezoneJS"] = new_timezone
            fp_mutated = Fingerprint(attributes, fp)

            if fp_mutated.constant_hash not in fp_constant_hash_to_next_node:
                fp_constant_hash_to_next_node[fp_mutated.constant_hash] = 0

            if i % 2 == 0:
                # we change every two fingerprints since its
                # the number of fingerprints per user
                fp_constant_hash_to_next_node[fp_mutated.constant_hash] = (fp_constant_hash_to_next_node[
                                                                               fp_mutated.constant_hash] + 1) % NB_PROCESSES

            node_to_send = fp_constant_hash_to_next_node[fp_mutated.constant_hash]
            parent_conn_list[node_to_send].send(fp_mutated)
            parent_conn_list[node_to_send].send("CONTINUE")

    print("There are %d ids" % total_nb_ids)

    for conn in parent_conn_list:
        conn.send("STOP")
        nb_ids = conn.recv()
        print("There are %d different ids on each nodes" % nb_ids)

    # Fingerprints have been distributed, we can start to measure
    print("Start 2nd fake sql query")
    cur.execute("SELECT *, NULL as canvasJS FROM extensionDataScheme LIMIT 1000, 2000")
    print("Finish 2nd fake sql query")
    fps = cur.fetchall()
    nb_iter = 0
    limit_iter = 100
    if NB_PROCESSES < 8:
        limit_iter = 30
    times = []
    index_to_add = 0
    for fp in fps:
        print("Iter %d" % nb_iter)
        if nb_iter == limit_iter:
            for conn in parent_conn_list:
                conn.send("STOP")
            break
        else:
            for conn in parent_conn_list:
                conn.send("CONTINUE")

        s = string.ascii_uppercase + string.digits
        new_user_id = ''.join(random.sample(s, 10))

        new_canvas_hashed = fp["canvasJSHashed"][:-4] + \
                            str(random.randint(0, 2000))
        new_timezone = str(random.randint(0, 2000))

        fp["id"] = new_user_id
        fp["canvasHashed"] = new_canvas_hashed
        fp["timezoneJS"] = new_timezone
        fp_mutated = Fingerprint(attributes, fp)

        start = time.time()
        for conn in parent_conn_list:
            conn.send(fp_mutated)

        node_to_prediction = list()
        exact_matching = list()
        for conn in parent_conn_list:
            node_to_prediction.append(conn.recv())
            if node_to_prediction[-1] is not None and node_to_prediction[-1][1] == 0:
                exact_matching.append(node_to_prediction[-1])

        node_to_add_fp_test = 0
        if node_to_prediction.count(None) == len(node_to_prediction):
            prediction = "None"
        elif len(exact_matching) > 0:
            if len(exact_matching) == 1 or candidates_have_same_id(exact_matching):
                prediction = (exact_matching[0][0], 0)
        elif candidates_have_same_id_bench(node_to_prediction):
            # we find one node not null
            index_nn = 0
            for i in range(0, len(node_to_prediction)):
                if node_to_prediction[i] is not None:
                    index_nn = i
                    break
            prediction = (node_to_prediction[index_nn][0], node_to_prediction[index_nn][1])
            node_to_add_fp_test = index_nn
        else:
            prediction = "None"

        # doens't matter for the benchmark

        # then we communicate our decision to all of the nodes/processes
        for i in range(0, NB_PROCESSES):
            if i == node_to_add_fp_test:
                parent_conn_list[i].send("KEEP")
            else:
                parent_conn_list[i].send("DISCARD")

        end = time.time()
        times.append(end - start)
        print(end - start)

        nb_iter += 1

    p.close()
    p.terminate()
    p.join()
    print(results)

    times = np.asarray(times)
    print("avg time : %f" % np.mean(times))
    print("min time: %f" % np.min(times))
    print("max time: %f" % np.max(times))
    print("25pct : %f" % np.percentile(times, 25))
    print("50pct : %f" % np.percentile(times, 50))
    print("75pct : %f" % np.percentile(times, 75))
    return (np.mean(times),
            np.min(times),
            np.max(times),
            np.percentile(times, 25),
            np.percentile(times, 50),
            np.percentile(times, 75)
            )