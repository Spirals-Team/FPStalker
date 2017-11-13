from fingerprint import Fingerprint
import MySQLdb as mdb


def get_consistent_ids(cur):
    """
        Returns a list of user ids having only consistent fingerprints
    """

    batch_size = 5000
    attributes = Fingerprint.INFO_ATTRIBUTES + Fingerprint.HTTP_ATTRIBUTES + \
                     Fingerprint.JAVASCRIPT_ATTRIBUTES + Fingerprint.FLASH_ATTRIBUTES
    counter_to_os = dict()
    counter_to_browser = dict()
    id_to_oses = dict()
    id_to_browsers = dict()
    id_to_nb_inconsistencies = dict()
    id_to_nb_fps = dict()

    cur.execute('SELECT max(counter) as nb_fps from extensionData')
    nb_fps = cur.fetchone()["nb_fps"] +1

    for i in range(0, nb_fps, batch_size):
        print(i)
        sql = "SELECT * FROM extensionData where counter < %s and counter > %s"
        cur.execute(sql, (i + batch_size, i))
        fps = cur.fetchall()
        for fp_dict in fps:
            try:
                fp = Fingerprint(attributes, fp_dict)
                counter_to_os[fp.getCounter()] = fp.getOs()
                counter_to_browser[fp.getCounter()] = fp.getBrowser()
                counter = fp.getCounter()

                if fp.getId() in id_to_oses:
                    id_to_oses[fp.getId()].add(fp.getOs())
                else:
                    id_to_oses[fp.getId()] = set()
                    id_to_oses[fp.getId()].add(fp.getOs())

                if fp.getId() in id_to_browsers:
                    id_to_browsers[fp.getId()].add(fp.getBrowser())
                else:
                    id_to_browsers[fp.getId()] = set()
                    id_to_browsers[fp.getId()].add(fp.getBrowser())

                if len(id_to_browsers[fp.getId()]) > 1 or len(id_to_oses[fp.getId()]) > 1:
                    id_to_nb_inconsistencies[fp.getId()] = 100000000

                if counter_to_os[counter] == "Android" or counter_to_os[counter] == "iOS" or \
                counter_to_os[counter] == "Windows Phone" or counter_to_os[counter] == "Firefox OS" or \
                counter_to_os[counter] == "Windows 95":
                    id_to_nb_inconsistencies[fp.getId()] = 10000000000

                if counter_to_browser[counter] == "Safari" or counter_to_browser[counter] == "IE" or \
                counter_to_browser[counter] == "Edge" or counter_to_browser[counter] == "Googlebot":
                    id_to_nb_inconsistencies[fp.getId()] = 10000000

                if fp.hasPlatformInconsistency():
                    if fp.getId() in id_to_nb_inconsistencies:
                        id_to_nb_inconsistencies[fp.getId()] += 5
                    else:
                        id_to_nb_inconsistencies[fp.getId()] = 5

                if fp.getId() in id_to_nb_fps:
                    id_to_nb_fps[fp.getId()] += 1
                else:
                    id_to_nb_fps[fp.getId()] = 1

                # Seems weird but made on purpose !
                if fp.getId() not in id_to_nb_inconsistencies:
                    id_to_nb_inconsistencies[fp.getId()] = 0

            except:
                id_to_nb_inconsistencies[fp_dict["id"]] = 1000000

    user_id_consistent = [x for x in id_to_nb_fps if
                          float(id_to_nb_inconsistencies[x])/float(id_to_nb_fps[x]) < 0.02]
    # we remove user that poison their canvas
    # we select users that changed canvas too frequently
    cur.execute("SELECT id, count(distinct canvasJSHashed) as count, count(canvasJSHashed) as \
                nb_fps FROM extensionData group by id having count(distinct canvasJSHashed)/count(canvasJSHashed) > 0.35 \
                and count(canvasJSHashed) > 5 order by id")
    rows = cur.fetchall()
    poisoner_ids = [row["id"] for row in rows]
    user_id_consistent = [user_id for user_id in user_id_consistent if user_id not in poisoner_ids]

    return user_id_consistent


def get_fingerprints_experiments(cur, min_nb_fingerprints, attributes, id_file="./data/consistent_extension_ids.csv"):
    """
        Returns a list of the fingerprints to use for the experiment
        We get only fingerprints whose associated user has at least
        min_nb_fingerprints and who have no inconsistency
    """
    with open(id_file, "r") as f:
        # we jump header
        f.readline()
        ids_query = []

        for line in f.readlines():
            ids_query.append("'" + line.replace("\n", "") + "'")

        ids_query = ",".join(ids_query)
        cur.execute("SELECT *, NULL as canvasJS FROM extensionData WHERE \
                    id in ("+ids_query+") and \
                    id in (SELECT id FROM extensionData GROUP BY \
                    id having count(*) > "+str(min_nb_fingerprints)+")\
                    ORDER by counter ASC")
        fps = cur.fetchall()
        fp_set = []
        for fp in fps:
            try:
                fp_set.append(Fingerprint(attributes, fp))
            except Exception as e:
                print(e)

        return fp_set
